use std::{
    collections::HashMap,
    iter::FromIterator,
    process::Child,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;
#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
    static ref CHILDREN : Children = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    #[cfg(all(windows, not(feature = "inline")))]
    unsafe {
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        let children: Children = Default::default();
        std::thread::spawn(move || check_zombie(children));
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let cmd = iter.next().unwrap().clone();
        let id = iter.next().unwrap().clone();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> = serde_json::from_str(&get_options()).unwrap();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.0);
        v.push(x.1);
        v.push(x.3);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers()
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(id)
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

pub fn check_zombie(children: Children) {
    let mut deads = Vec::new();
    loop {
        let mut lock = children.lock().unwrap();
        let mut n = 0;
        for (id, c) in lock.1.iter_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                deads.push(id.clone());
                n += 1;
            }
        }
        for ref id in deads.drain(..) {
            lock.1.remove(id);
        }
        if n > 0 {
            lock.0 = true;
        }
        drop(lock);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

#[inline]
pub fn new_remote(id: String, remote_type: String, force_relay: bool) {
    let mut lock = CHILDREN.lock().unwrap();
    let mut args = vec![format!("--{}", remote_type), id.clone()];
    if force_relay {
        args.push("".to_string()); // password
        args.push("--relay".to_string());
    }
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                return;
            }
        }
    }
    match crate::run_me(args) {
        Ok(child) => {
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
}

#[inline]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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jt0X3DX4Yts5iIiIStGHf1H5kbWtrY97Ho98O14sACfY2ubmpz70HdxgOwcREVGpeXT75t+2dXTssZ2jFLAAnGC9/X29/2pv/aPtHERERKXkNbcnX7Bmy+Y1tnOUChaAk2DDtm0bzr8t+ULbOYiIiErBW2/vP+/fa9dy2sYE4kkgk6Slu6tle/+sba85SZ5vOwsREVGxuubekRv/d/WT39Pa8Li3CcQO4CQxxph/b936V9s5iIiIitm69vY/+r72becoNSwAJ9Ge9o49531j5BzbOYiIiIrRBV/ve82G1tb1tnOUIl4CnmSDw8P9zR0zd778ZPNq21mIiIiKxfu/NfbB3zz55Pe14aXfycAO4CTrHxzof7S1mZeCiYiIjsKagYE/e77PeX+ThAXgFNiyc8eW197Sc7btHERERMXgAw/479nS0rLFdo5SxgJwijy8fu3Db/7W6IW2cxARERW6hzv2/GlkdHTEdo5SxjWAU2g0nenbtae+96UnCx4XR0REdBCv+lrnGau3bFltO0epYwdwCnV0d3c82tn+W9s5iIiICtHr7ux96SMbNjxiO0c5YAE4xdZu2bL6ott7X2I7BxERUSF58y3dFzy8es2fbecoF7wEbMHOzs4d25Kzd77mFPl621mIiIhsu/jWnnf8edPGn2mtOfJlirADaMlj23lKCBER0WVf2vPuBzdv+rHv+zztYwqxALSkpaOj5RW39JxuOwcREZFNv9+14750Npu2naPcsAC06LEN6x57850D59rOQUREZMNLP7vzTBZ/dnANoGXNHe3NG3qmb3/9Ke75trMQERFNlcvuSV39z80b/pdHvdnBDmABeKp5x4Mfvd/7jO0cREREU2VD+24e9WYRC8ACsLujc/djvd3/z3YOIiKiqfD6O7pftG3P7m22c5QzFoAF4olNmx57wx0DPCGEiIhK2ttu7znvn6vX/dUYY2xnKWdcA1hAdnS271jXN3vteSfLN9rOQkRENNGu+6655n/+858f2M5B7AAWnP9sWP+PD35P3mA7BxER0UR7dPvWP7LzVxhYABaY7mRv98O7d/6f7RxEREQT6TVf63rBtj17uO6vQLAALECbtm/f9KqbO8+wnYOIiGgivPmW5Kse2bTxn7Zz0D4sAAvUIxs3PPL6O3pfaDsHERHR8Tjv9uTr/rRh7e94zm9hYQFYwB5as+bvb7q9jyeFEBFRUXrj17oufHj9ut9w3V/hYQFYwIwx5s9rV//pjXcOvNp2FiIioqPx7m97V/1t86Zf+b72bWehp2MBWOCMMeava5763du/1nOR7SxERERH6tEdzX/gSR+Fi3MAi4AxxjT3Jjev31Wz6fWnRy6wnYeIiOiZvObWnrPXbt+21nYOOjQWgEXCGGN29vRs2bgxvP21Z1e83nYeIiKig3nD17pf/tDGDX/nur/CxgKwiPha+9sH+jY8tk61XvjcqtfYzkNERDTeBXf0vvbvG9b/njt+Cx8LwCKjtdZtQ0MbnnwKbec/v/pVtvMQEREBwFtvS57/l7Vrf83OX3FgAViEPK29lpHhtZt2Vmdee3rkHNt5iIiovL3p9t6L/rhu7X+z+Cse3AVcpDLZbHpbf9+vbecgIqLy9rabut7yVxZ/RYcFYBFbt2vnmtff1vZy2zmIiKg8vem2nrf+ceumn/mas/6KDS8BF7nW7t7mJ7a5T154ZtWbbGchIqLy8c4vtb3jz9u2/Jiz/ooTC8ASsKOnd8t/9iSeeMOzw2+2nYWIiErfW28fuOS3G9d9l7t9ixcLwBLR2tW57Ylt8ScvPDPGTiAREU2aK29KvuP3m9f9iMVfcWMBWCKMMWZnsmfLY82V6y86I8Zj44iIaMK9+abuS/9v28YfZD0vazsLHR8WgCXEGGNakz1b1m+LbXz9mfELbechIqLScckX9lzx153bfpDxvIztLHT8WACWGG2M3t6b3PjE9opNF54R47nBRER03C7+Wvdlf2re+l0Wf6WDBWAJMsaY1t7k5q3bq7e85ozI+bbzEBFR8brkC7sv+8uO7ez8lRgWgCVKa6239HSvf3JzfNsFZ8XOs52HiIiKz5u+3H7ZX1t2/CCTzaZtZ6GJxQKwhBljzK6+5IYN62NbX/fcODuBRER0xN72+d2X/61lxw9Z/JUmFoAlThujt/X3rP9Pc9Wmi86Ick0gEREd1hu+uOeKv+zc/u2s73O3b4liAVgGjDFmd29y81ObYxvOP4u7g4mI6NAu+WLb5X9v2fnDrM81f6WMBWCZ0FrrHb09Gx/fFt94IUfEEBHRQbz5K12X/2Xn1u+lPV72LXUsAMuIMca09CY3bdpeueG1Z0RZBBIR0V5v/8Keyx/ctf373O1bHlgAlhltjN6a7Nn06M7KtW94TvQNtvMQEZF9b72l551/at7KUS9lhAVgGTLGmN09PVs2tNSsfd3pERaBRERl7NKvdLzzD9s283i3MsMCsExpY/SWzo6NT+4Ir7vwjEoWgUREZeji25Lv+OPWzT9k8Vd+WACWuR3dyY3bm+PrXnNGnEUgEVEZuewr7e/8A4u/ssUCkLCpu3vjY20NT1z0rNCbbWchIqLJ96Zbk2//3cb139Vaa9tZyA4WgAQAaOns2PbE9qpHLzwj+hbbWYiIaPJcdnPPxX/asvGnLP7KGwtAAhBsDNnR3bntsZbqRy46PXqx7TxERDTx3nBLz5v/tHnDzzzf92xnIbtYANJ+dnV1Na/eUf3I+c9hEUhEVErefmvvRX/euP4XvvZ921nIPmE7ABWm56066SX/fV3dH23nICKi43fRHX2vf3DN6l8bY4ztLFQYpO0AVJgeWrf2Lxfe1neO7RxERHR83nJb72tZ/NGB2AGkZ3T6ilWn//aGxCO2cxAR0dE777bkyx5av+5P3PBBB+IaQHpGe7o69/x2Q+gXWzZXtLz4VPES23mIiOjInHd73/MfWr/2byz+6GDYAaQjUlNVVbN09uyT/vfGaQ/azkJERId21f2Z9zzeuuv3O1p3b7edhQoXC0A6YkIIEXHd6Ktnz7vs7o/MvN12HiIi2t9bvtb9hr9u2fQ/PN2DDoeXgOmoeL6f3To08OQjm0Ktbzir8jW28xARUeD823tf8+CG9b/2fY55ocNjAUhHTWut2wYG1q/fFG1+3Vnx19nOQ0RU7t50a+/L/rZ+7f9xvR8dKRaAdEx8rf1tvcm1j22Lb7jozNiFtvMQEZWrV9zUefZDG9f/jWNe6GhwDSAdF6WUetnSFa/87o11v7adhYionLz3W9mrH2rZ8afm9rbtLP7oaLEApOMmhBCnr1xxzm+uq/+z7SxEROXgjbf3nfeXtat/xcKPjhULQJowZy9fcfavbmz4p+0cRESl7E239b30z+tW/5nFHx0PFoA0oZYtWbzizKXLXveV1wx+znYWIqJS8s5vpa9bt2f373e0tmy1nYWKHzeB0ITqSSa7+oaHW5/aVfvkq04W59nOQ0RUCt5ya+8Ff16z+kfJ/r5u21moNLADSJOiqrKyatXixav+5+qqf9jOQkRUzC68s+/lf1+z5o8c8UITiQUgTRohhJjXNGPe2bPnn3PrFe59tvMQERWb82/ufOE/N2/6B4s/mmgsAGnSSSnl2StXvey/r639re0sRETF4Jrv+e/b0N7+h/Vbt63nZg+aDCwAaUpIKeVzT1zx3F/ekPib7SxERIXsHfeMvP7RHdv/1dWT7LKdhUoXN4HQlDDGmF1dnbv+b3PkV5vamna/ZHnmRbYzEREVmpff2n3Gg089+eeR0bER21motLEDSFNu3szZ806ZO/+sb16qfmA7CxFRIfjwt/Gef7a1/HlT8/ZNtrNQeWABSFZEIpHI4hNOWHzK9Fnn3Pym9K228xAR2XDjD533PbV71x+3tbRsG0ulxmznofLBApCsmjtj5tyTps04+f73VPyP7SxERFPprbf0vvaPm9b91vd933YWKj8sAMk6IYRwXTd0zvKTzv/Buyt+aDsPEdFkuuqbY9c/1d72h20tLbzcS9awAKSCoZRSL1q68sU/urH2/2xnISKaDG+7ve/1f9qw7rdZz8vazkLljbuAqWAYY0xzd8f2328K/8+aHXXNL1ulX2o7ExHRRHn5rT3P+/tanuhBhYEdQCpIjYn6xmfNO+FZ37k6+r+2sxARHY9P/yz+ob81b/392m1b1nKoMxUKFoBU0ObOnDXvlDkLX/Cty+S3bWchIjpa598z/Optra1PtnV0tNnOQjQeC0AqeFJK+bxlq573ixtrH7SdhYjoSFz6jaHXP9Xe/mRnT3dnJpPNsPNHhYYFIBWNGY2NM09ZuOis71zq/tR2FiKig3ndLT3nbu1oW9Pd29vFoo8KGQtAKipKKXXy/IWnnDx99ou+/A79Zdt5iIgA4PKvJt/xfzs2/TSVzaZY+FExYAFIRamhrq7h5IWLT/7RldE/2M5CROXtdV/rfsm/N2180Ncc6EzFgwUgFS0ppZw3vWnec2bMOfOOqyLft52HiMrLdd/yLn20Zcc/mjvamjnahYoNC0AqCcuXLDl1ZdOsF9/5Vv0V21mIqLR94Jve+x5tb/3j+pada21nITpWLACpZExvmDb9tDnznv2dq+O/tp2FiErTxbf0vvIvm9f/iSd5ULFjAUglZ9mChctXzpz9vLsuEXfbzkJEpeHSe8feuWZ36993tbft4CYPKgUsAKkk1VbX1C6bM2/ZisqaM79wqbjJdh4iKk6f+qb/6ScGev7w7y2b/s11flRKWABSSYvForE5jdPnLm6cfvr9l0e+bTsPERWHd38r+4lOeP9Ys2nTmt7+/l7beYgmGgtAKguOUs7SmbOWntbQ9Lybr47eZTsPERWmD92V+tDGkf6Ht3V3bunp7+9h149KFQtAKitCCHHK0iXPmd9Q/6J73u5+3nYeIiocr72l59xHN234q+f7nu0sRJONBSCVHSGEaEwkGlfNnXfSD6+u/L3tPERk15VfH3nTk517/rOzo30nO35ULlgAUlmrraqqnT+96YQl9dPPuuNSeavtPEQ0dd5+f+YNa3Y0P7qno6OFO3up3LAAJEKwRvAFy1a+4Cc31P7JdhYimlzvuXvs4sc7dv9nW9uebSz8qFyxACQa54Q5cxctmTnrtO9cFvqR7SxENLHecu/omzbsbn1kd1vbTttZiGxjAUh0gFg0Gptel5i+tGnm0tnSfc7n3+V+wnYmIjp2n/i2uO6hzj1/X71182rbWYgKBQtAokMQQohoNBqrr6mZNruufumvbkj81nYmIjpyF9+ffd2Gnc2rO3t62jOZTMZ2HqJCwgKQ6AgIIUTYccPnLFj8iu99oOGXtvMQ0aFdcufQ69Z37FnT2t3V6vu+bzsPUSFiAUh0FIQQoqm+fubcxsaT/t8NDf9rOw8RBS7/xtilO/qSa1p7unb0Dgzw5A6iw2ABSHQMpJRywcxZC05rbHrW16+KccMIkQWfvE9/dE1v16O7epNb23qTbRzgTHTkWAASHQfHcZyGRKJh7vTpS+dU1Zx21yXyq7YzEZW6a+4auXZdT+c/N7a2rOYYF6JjwwKQaAIIIURNVVXNnETDnCV19Svvuir6PduZiErNtXeNXbq2p+M/m9t2b856XtZ2HqJixgKQaIIJIcT0+vqmpXPmrJgeipx+x2Whz9rORFTMzv/6wGub29ue2t3R0Wo7C1GpYAFINEn2dgXrG+acWFe/6o4ro9+1nYmoWLz/G2Mf2w39yLqdO9Z1Jns6eamXaGKxACSaAkIIUV1ZWT2rYdrc+fXTTn7givC3bWciKjTv/57+VOvIyBPNHR3rO3p62sdSqTHbmYhKFQtAoimmlFJzpzXOXTlz7kn3XRXhTEEqe9fePfzOLQP9a3cle3b1Dgz0aq217UxEpY4FIJElQgiRqK1NLJgxY9GsurqV975d3WM7E9FUufq+1AdaU6NP7Ni9Z1N3sreDRR/R1GIBSFQAYtForLaisrY+XlFfH4rMmC7dxbe9v+5W27mIJtLnvis/sX1kcPWW7q7N7b3J9sHh4UHbmYjKFQtAogLkKOUsmjP3xAWJhlO/c1XsAdt5iI7VxbcPXLxnqH9L78hwR//QUO/o2Nio7UxExAKQqKDFotFYXWVVXX00Vl/rRqbVO6HZd7+/7lu2cxEdznvuTl38VHf7E1t3t271Nc/jJSo0LACJiozrOO68GTNPXNI468xvXxm623YeIgB43w/xsa7U2Nbdyd4tbd3drf0Dg/2+z8KPqFCxACQqUlJKecKMmSecNG36SXdfU/FT23mo/Fz3zbF3bk72rE+OjHT3jQz3jY6lRrPZLE/oICoCLACJipwQQoRcN1QRj1c21NU2zayrX/qTK+MsCGnCXH577+e6s9l1/alUy0gmnRwZGxsYHhsbGuN6PqKixQKQqMRIKWVDbW3DgqYZCxZW1S679VJ1n+1MVJyuvXv0ivXdHY9vbm/bkPG8DADwRA6i0sACkKiEKaVUJByOxKPRimgoXBELharjbihRHQ7P+8mN9ffazkeF5QPf1p/sGBvdtLuvd2tHX++e3sHBJNfxEZUmFoBEZUYIIZSUatGs2YuW1tWvWFSdWPbBt2Y+bTsXTb0PPOBfs7Wne8NgKtU3kBobGBgdGRgcGRnkUGai0scCkKiMCSGE67puJByOxiKReCwcrqoIReqmxeNzf3x93Q9t56OJc/23vU93p8Y2dQ4ONPcODnb2DQ33Do+MDNnORUR2sAAkoqdRSqnZjdNnL6pvWLSgtn7BtEhkxvUXjXzCdi46cp9+QHy0Izu2bVdfclf38FB33/BwH7t7RJTHApCInpGUUiqlVMh1Q+FQKBJynYjjOJFIKBSvgKoIKxVXBnHp+xVIZypk1qv95VdO/ILt3OXg6u/4n2zr610/MDraNpbJDqSzmeGxdHpkNJUazWSzGa7fI6JDYQFIRMdF5AFCQAjAIKSc8LNnzX3eonj1mV+6oZKdwwn0mR+F39cxNrp7Z29yZ0uyq6UrmexiV4+IjhYLQCKaNLFINBaPRSvCbigactyoq1Q0JFU8Fo4kpsWr5j5wTeQ22xkLyXU/kB/MGD045mUGBkZGk/2jI13Jvv7ukdHR4XQ2k/Y839Naa45iIaLjxQKQiKZU0CwEpJCyrrKyrqYiXhN13WhYqHBIykhIymilG6qZHq+Y9YUrIzfbzjsZbv5p9KPtQ4PtLanRlrbeZNtYOjOW8bxM1veyWW/fi+/7Prt7RDQZWAASUUGSUspwKBSOhMMRJZXjOspVUjpSSKWUdJSUjjTClVI6QggpACWEUAKQAKQApDFG5gvOg/GfsZNmjBDSGGO0AQyCFw3AGBittfEhhae19nytPWOM7+f+7Gvf83w/+HNQxPm+7/uev6+Dxy4eEdnEApCISsozFXwHYhFGREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREE+3/AyHOYKvL+lG2AAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDIyLTExLTA0VDAyOjQxOjA1KzAwOjAwKQfauwAAACV0RVh0ZGF0ZTptb2RpZnkAMjAyMi0xMS0wNFQwMjo0MTowNSswMDowMFhaYgcAAAAASUVORK5CYII=".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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jt0X3DX4Yts5iIiIStGHf1H5kbWtrY97Ho98O14sACfY2ubmpz70HdxgOwcREVGpeXT75t+2dXTssZ2jFLAAnGC9/X29/2pv/aPtHERERKXkNbcnX7Bmy+Y1tnOUChaAk2DDtm0bzr8t+ULbOYiIiErBW2/vP+/fa9dy2sYE4kkgk6Slu6tle/+sba85SZ5vOwsREVGxuubekRv/d/WT39Pa8Li3CcQO4CQxxph/b936V9s5iIiIitm69vY/+r72becoNSwAJ9Ge9o49531j5BzbOYiIiIrRBV/ve82G1tb1tnOUIl4CnmSDw8P9zR0zd778ZPNq21mIiIiKxfu/NfbB3zz55Pe14aXfycAO4CTrHxzof7S1mZeCiYiIjsKagYE/e77PeX+ThAXgFNiyc8eW197Sc7btHERERMXgAw/479nS0rLFdo5SxgJwijy8fu3Db/7W6IW2cxARERW6hzv2/GlkdHTEdo5SxjWAU2g0nenbtae+96UnCx4XR0REdBCv+lrnGau3bFltO0epYwdwCnV0d3c82tn+W9s5iIiICtHr7ux96SMbNjxiO0c5YAE4xdZu2bL6ott7X2I7BxERUSF58y3dFzy8es2fbecoF7wEbMHOzs4d25Kzd77mFPl621mIiIhsu/jWnnf8edPGn2mtOfJlirADaMlj23lKCBER0WVf2vPuBzdv+rHv+zztYwqxALSkpaOj5RW39JxuOwcREZFNv9+14750Npu2naPcsAC06LEN6x57850D59rOQUREZMNLP7vzTBZ/dnANoGXNHe3NG3qmb3/9Ke75trMQERFNlcvuSV39z80b/pdHvdnBDmABeKp5x4Mfvd/7jO0cREREU2VD+24e9WYRC8ACsLujc/djvd3/z3YOIiKiqfD6O7pftG3P7m22c5QzFoAF4olNmx57wx0DPCGEiIhK2ttu7znvn6vX/dUYY2xnKWdcA1hAdnS271jXN3vteSfLN9rOQkRENNGu+6655n/+858f2M5B7AAWnP9sWP+PD35P3mA7BxER0UR7dPvWP7LzVxhYABaY7mRv98O7d/6f7RxEREQT6TVf63rBtj17uO6vQLAALECbtm/f9KqbO8+wnYOIiGgivPmW5Kse2bTxn7Zz0D4sAAvUIxs3PPL6O3pfaDsHERHR8Tjv9uTr/rRh7e94zm9hYQFYwB5as+bvb7q9jyeFEBFRUXrj17oufHj9ut9w3V/hYQFYwIwx5s9rV//pjXcOvNp2FiIioqPx7m97V/1t86Zf+b72bWehp2MBWOCMMeava5763du/1nOR7SxERERH6tEdzX/gSR+Fi3MAi4AxxjT3Jjev31Wz6fWnRy6wnYeIiOiZvObWnrPXbt+21nYOOjQWgEXCGGN29vRs2bgxvP21Z1e83nYeIiKig3nD17pf/tDGDX/nur/CxgKwiPha+9sH+jY8tk61XvjcqtfYzkNERDTeBXf0vvbvG9b/njt+Cx8LwCKjtdZtQ0MbnnwKbec/v/pVtvMQEREBwFtvS57/l7Vrf83OX3FgAViEPK29lpHhtZt2Vmdee3rkHNt5iIiovL3p9t6L/rhu7X+z+Cse3AVcpDLZbHpbf9+vbecgIqLy9rabut7yVxZ/RYcFYBFbt2vnmtff1vZy2zmIiKg8vem2nrf+ceumn/mas/6KDS8BF7nW7t7mJ7a5T154ZtWbbGchIqLy8c4vtb3jz9u2/Jiz/ooTC8ASsKOnd8t/9iSeeMOzw2+2nYWIiErfW28fuOS3G9d9l7t9ixcLwBLR2tW57Ylt8ScvPDPGTiAREU2aK29KvuP3m9f9iMVfcWMBWCKMMWZnsmfLY82V6y86I8Zj44iIaMK9+abuS/9v28YfZD0vazsLHR8WgCXEGGNakz1b1m+LbXz9mfELbechIqLScckX9lzx153bfpDxvIztLHT8WACWGG2M3t6b3PjE9opNF54R47nBRER03C7+Wvdlf2re+l0Wf6WDBWAJMsaY1t7k5q3bq7e85ozI+bbzEBFR8brkC7sv+8uO7ez8lRgWgCVKa6239HSvf3JzfNsFZ8XOs52HiIiKz5u+3H7ZX1t2/CCTzaZtZ6GJxQKwhBljzK6+5IYN62NbX/fcODuBRER0xN72+d2X/61lxw9Z/JUmFoAlThujt/X3rP9Pc9Wmi86Ick0gEREd1hu+uOeKv+zc/u2s73O3b4liAVgGjDFmd29y81ObYxvOP4u7g4mI6NAu+WLb5X9v2fnDrM81f6WMBWCZ0FrrHb09Gx/fFt94IUfEEBHRQbz5K12X/2Xn1u+lPV72LXUsAMuIMca09CY3bdpeueG1Z0RZBBIR0V5v/8Keyx/ctf373O1bHlgAlhltjN6a7Nn06M7KtW94TvQNtvMQEZF9b72l551/at7KUS9lhAVgGTLGmN09PVs2tNSsfd3pERaBRERl7NKvdLzzD9s283i3MsMCsExpY/SWzo6NT+4Ir7vwjEoWgUREZeji25Lv+OPWzT9k8Vd+WACWuR3dyY3bm+PrXnNGnEUgEVEZuewr7e/8A4u/ssUCkLCpu3vjY20NT1z0rNCbbWchIqLJ96Zbk2//3cb139Vaa9tZyA4WgAQAaOns2PbE9qpHLzwj+hbbWYiIaPJcdnPPxX/asvGnLP7KGwtAAhBsDNnR3bntsZbqRy46PXqx7TxERDTx3nBLz5v/tHnDzzzf92xnIbtYANJ+dnV1Na/eUf3I+c9hEUhEVErefmvvRX/euP4XvvZ921nIPmE7ABWm56066SX/fV3dH23nICKi43fRHX2vf3DN6l8bY4ztLFQYpO0AVJgeWrf2Lxfe1neO7RxERHR83nJb72tZ/NGB2AGkZ3T6ilWn//aGxCO2cxAR0dE777bkyx5av+5P3PBBB+IaQHpGe7o69/x2Q+gXWzZXtLz4VPES23mIiOjInHd73/MfWr/2byz+6GDYAaQjUlNVVbN09uyT/vfGaQ/azkJERId21f2Z9zzeuuv3O1p3b7edhQoXC0A6YkIIEXHd6Ktnz7vs7o/MvN12HiIi2t9bvtb9hr9u2fQ/PN2DDoeXgOmoeL6f3To08OQjm0Ktbzir8jW28xARUeD823tf8+CG9b/2fY55ocNjAUhHTWut2wYG1q/fFG1+3Vnx19nOQ0RU7t50a+/L/rZ+7f9xvR8dKRaAdEx8rf1tvcm1j22Lb7jozNiFtvMQEZWrV9zUefZDG9f/jWNe6GhwDSAdF6WUetnSFa/87o11v7adhYionLz3W9mrH2rZ8afm9rbtLP7oaLEApOMmhBCnr1xxzm+uq/+z7SxEROXgjbf3nfeXtat/xcKPjhULQJowZy9fcfavbmz4p+0cRESl7E239b30z+tW/5nFHx0PFoA0oZYtWbzizKXLXveV1wx+znYWIqJS8s5vpa9bt2f373e0tmy1nYWKHzeB0ITqSSa7+oaHW5/aVfvkq04W59nOQ0RUCt5ya+8Ff16z+kfJ/r5u21moNLADSJOiqrKyatXixav+5+qqf9jOQkRUzC68s+/lf1+z5o8c8UITiQUgTRohhJjXNGPe2bPnn3PrFe59tvMQERWb82/ufOE/N2/6B4s/mmgsAGnSSSnl2StXvey/r639re0sRETF4Jrv+e/b0N7+h/Vbt63nZg+aDCwAaUpIKeVzT1zx3F/ekPib7SxERIXsHfeMvP7RHdv/1dWT7LKdhUoXN4HQlDDGmF1dnbv+b3PkV5vamna/ZHnmRbYzEREVmpff2n3Gg089+eeR0bER21motLEDSFNu3szZ806ZO/+sb16qfmA7CxFRIfjwt/Gef7a1/HlT8/ZNtrNQeWABSFZEIpHI4hNOWHzK9Fnn3Pym9K228xAR2XDjD533PbV71x+3tbRsG0ulxmznofLBApCsmjtj5tyTps04+f73VPyP7SxERFPprbf0vvaPm9b91vd933YWKj8sAMk6IYRwXTd0zvKTzv/Buyt+aDsPEdFkuuqbY9c/1d72h20tLbzcS9awAKSCoZRSL1q68sU/urH2/2xnISKaDG+7ve/1f9qw7rdZz8vazkLljbuAqWAYY0xzd8f2328K/8+aHXXNL1ulX2o7ExHRRHn5rT3P+/tanuhBhYEdQCpIjYn6xmfNO+FZ37k6+r+2sxARHY9P/yz+ob81b/392m1b1nKoMxUKFoBU0ObOnDXvlDkLX/Cty+S3bWchIjpa598z/Optra1PtnV0tNnOQjQeC0AqeFJK+bxlq573ixtrH7SdhYjoSFz6jaHXP9Xe/mRnT3dnJpPNsPNHhYYFIBWNGY2NM09ZuOis71zq/tR2FiKig3ndLT3nbu1oW9Pd29vFoo8KGQtAKipKKXXy/IWnnDx99ou+/A79Zdt5iIgA4PKvJt/xfzs2/TSVzaZY+FExYAFIRamhrq7h5IWLT/7RldE/2M5CROXtdV/rfsm/N2180Ncc6EzFgwUgFS0ppZw3vWnec2bMOfOOqyLft52HiMrLdd/yLn20Zcc/mjvamjnahYoNC0AqCcuXLDl1ZdOsF9/5Vv0V21mIqLR94Jve+x5tb/3j+pada21nITpWLACpZExvmDb9tDnznv2dq+O/tp2FiErTxbf0vvIvm9f/iSd5ULFjAUglZ9mChctXzpz9vLsuEXfbzkJEpeHSe8feuWZ36993tbft4CYPKgUsAKkk1VbX1C6bM2/ZisqaM79wqbjJdh4iKk6f+qb/6ScGev7w7y2b/s11flRKWABSSYvForE5jdPnLm6cfvr9l0e+bTsPERWHd38r+4lOeP9Ys2nTmt7+/l7beYgmGgtAKguOUs7SmbOWntbQ9Lybr47eZTsPERWmD92V+tDGkf6Ht3V3bunp7+9h149KFQtAKitCCHHK0iXPmd9Q/6J73u5+3nYeIiocr72l59xHN234q+f7nu0sRJONBSCVHSGEaEwkGlfNnXfSD6+u/L3tPERk15VfH3nTk517/rOzo30nO35ULlgAUlmrraqqnT+96YQl9dPPuuNSeavtPEQ0dd5+f+YNa3Y0P7qno6OFO3up3LAAJEKwRvAFy1a+4Cc31P7JdhYimlzvuXvs4sc7dv9nW9uebSz8qFyxACQa54Q5cxctmTnrtO9cFvqR7SxENLHecu/omzbsbn1kd1vbTttZiGxjAUh0gFg0Gptel5i+tGnm0tnSfc7n3+V+wnYmIjp2n/i2uO6hzj1/X71182rbWYgKBQtAokMQQohoNBqrr6mZNruufumvbkj81nYmIjpyF9+ffd2Gnc2rO3t62jOZTMZ2HqJCwgKQ6AgIIUTYccPnLFj8iu99oOGXtvMQ0aFdcufQ69Z37FnT2t3V6vu+bzsPUSFiAUh0FIQQoqm+fubcxsaT/t8NDf9rOw8RBS7/xtilO/qSa1p7unb0Dgzw5A6iw2ABSHQMpJRywcxZC05rbHrW16+KccMIkQWfvE9/dE1v16O7epNb23qTbRzgTHTkWAASHQfHcZyGRKJh7vTpS+dU1Zx21yXyq7YzEZW6a+4auXZdT+c/N7a2rOYYF6JjwwKQaAIIIURNVVXNnETDnCV19Svvuir6PduZiErNtXeNXbq2p+M/m9t2b856XtZ2HqJixgKQaIIJIcT0+vqmpXPmrJgeipx+x2Whz9rORFTMzv/6wGub29ue2t3R0Wo7C1GpYAFINEn2dgXrG+acWFe/6o4ro9+1nYmoWLz/G2Mf2w39yLqdO9Z1Jns6eamXaGKxACSaAkIIUV1ZWT2rYdrc+fXTTn7givC3bWciKjTv/57+VOvIyBPNHR3rO3p62sdSqTHbmYhKFQtAoimmlFJzpzXOXTlz7kn3XRXhTEEqe9fePfzOLQP9a3cle3b1Dgz0aq217UxEpY4FIJElQgiRqK1NLJgxY9GsurqV975d3WM7E9FUufq+1AdaU6NP7Ni9Z1N3sreDRR/R1GIBSFQAYtForLaisrY+XlFfH4rMmC7dxbe9v+5W27mIJtLnvis/sX1kcPWW7q7N7b3J9sHh4UHbmYjKFQtAogLkKOUsmjP3xAWJhlO/c1XsAdt5iI7VxbcPXLxnqH9L78hwR//QUO/o2Nio7UxExAKQqKDFotFYXWVVXX00Vl/rRqbVO6HZd7+/7lu2cxEdznvuTl38VHf7E1t3t271Nc/jJSo0LACJiozrOO68GTNPXNI468xvXxm623YeIgB43w/xsa7U2Nbdyd4tbd3drf0Dg/2+z8KPqFCxACQqUlJKecKMmSecNG36SXdfU/FT23mo/Fz3zbF3bk72rE+OjHT3jQz3jY6lRrPZLE/oICoCLACJipwQQoRcN1QRj1c21NU2zayrX/qTK+MsCGnCXH577+e6s9l1/alUy0gmnRwZGxsYHhsbGuN6PqKixQKQqMRIKWVDbW3DgqYZCxZW1S679VJ1n+1MVJyuvXv0ivXdHY9vbm/bkPG8DADwRA6i0sACkKiEKaVUJByOxKPRimgoXBELharjbihRHQ7P+8mN9ffazkeF5QPf1p/sGBvdtLuvd2tHX++e3sHBJNfxEZUmFoBEZUYIIZSUatGs2YuW1tWvWFSdWPbBt2Y+bTsXTb0PPOBfs7Wne8NgKtU3kBobGBgdGRgcGRnkUGai0scCkKiMCSGE67puJByOxiKReCwcrqoIReqmxeNzf3x93Q9t56OJc/23vU93p8Y2dQ4ONPcODnb2DQ33Do+MDNnORUR2sAAkoqdRSqnZjdNnL6pvWLSgtn7BtEhkxvUXjXzCdi46cp9+QHy0Izu2bVdfclf38FB33/BwH7t7RJTHApCInpGUUiqlVMh1Q+FQKBJynYjjOJFIKBSvgKoIKxVXBnHp+xVIZypk1qv95VdO/ILt3OXg6u/4n2zr610/MDraNpbJDqSzmeGxdHpkNJUazWSzGa7fI6JDYQFIRMdF5AFCQAjAIKSc8LNnzX3eonj1mV+6oZKdwwn0mR+F39cxNrp7Z29yZ0uyq6UrmexiV4+IjhYLQCKaNLFINBaPRSvCbigactyoq1Q0JFU8Fo4kpsWr5j5wTeQ22xkLyXU/kB/MGD045mUGBkZGk/2jI13Jvv7ukdHR4XQ2k/Y839Naa45iIaLjxQKQiKZU0CwEpJCyrrKyrqYiXhN13WhYqHBIykhIymilG6qZHq+Y9YUrIzfbzjsZbv5p9KPtQ4PtLanRlrbeZNtYOjOW8bxM1veyWW/fi+/7Prt7RDQZWAASUUGSUspwKBSOhMMRJZXjOspVUjpSSKWUdJSUjjTClVI6QggpACWEUAKQAKQApDFG5gvOg/GfsZNmjBDSGGO0AQyCFw3AGBittfEhhae19nytPWOM7+f+7Gvf83w/+HNQxPm+7/uev6+Dxy4eEdnEApCISsozFXwHYhFGREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREE+3/AyHOYKvL+lG2AAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDIyLTExLTA0VDAyOjQxOjA1KzAwOjAwKQfauwAAACV0RVh0ZGF0ZTptb2RpZnkAMjAyMi0xMS0wNFQwMjo0MTowNSswMDowMFhaYgcAAAAASUVORK5CYII=".into()
    }
}
