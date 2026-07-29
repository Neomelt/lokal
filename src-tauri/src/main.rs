// 禁掉 Windows release 下的控制台窗口。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    lokal_lib::run()
}
