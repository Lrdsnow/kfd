/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

import SwiftUI

struct ContentView: View {
    @State private var kfd: UInt64 = 0

    private var puaf_pages_options = [16, 32, 64, 128, 256, 512, 1024, 2048]
    @State private var puaf_pages_index = 7
    @State private var puaf_pages = 0

    private var puaf_method_options = ["physpuppet", "smith"]
    @State private var puaf_method = 1

    private var kread_method_options = ["kqueue_workloop_ctl", "sem_open"]
    @State private var kread_method = 1

    private var kwrite_method_options = ["dup", "sem_open"]
    @State private var kwrite_method = 1
    
    
    var body: some View {
        NavigationView {
            Form {
                Section {
                    VStack {
                        Button("Open Kernel") {
                            puaf_pages = puaf_pages_options[puaf_pages_index]
                            kfd = do_kopen(UInt64(puaf_pages), UInt64(puaf_method), UInt64(kread_method), UInt64(kwrite_method))
                        }.disabled(kfd != 0).frame(minWidth: 0, maxWidth: .infinity)
                        Button("Hide HomeBar") {
                            hide_homebar(kfd)
                        }.disabled(kfd == 0).frame(minWidth: 0, maxWidth: .infinity)
                        Button("Hide DarkMode Dock") {
                            hide_darkmode_dock(kfd)
                        }.disabled(kfd == 0).frame(minWidth: 0, maxWidth: .infinity)
                        Button("Hide LightMode Dock") {
                            hide_lightmode_dock(kfd)
                        }.disabled(kfd == 0).frame(minWidth: 0, maxWidth: .infinity)
                        Button("Hide LockScreen Icons") {
                            hide_lsicons(kfd)
                        }.disabled(kfd == 0).frame(minWidth: 0, maxWidth: .infinity)
                        Button("Close Kernel & Respring") {
                            do_kclose(kfd)
                            do_respring()
                        }.disabled(kfd == 0).frame(minWidth: 0, maxWidth: .infinity)
                    }.buttonStyle(.bordered)
                }.listRowBackground(Color.clear)
                if kfd != 0 {
                    Section {
                        VStack {
                            Text("Success!").foregroundColor(.green)
                            Text("Look at output in Xcode")
                        }.frame(minWidth: 0, maxWidth: .infinity)
                    }.listRowBackground(Color.clear)
                }
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
