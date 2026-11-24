package main

import "testing"

func TestGroupDevices(t *testing.T) {
	l := []PnPDev{
		{Instance: `HID\VID_046D&PID_C539&MI_01\7&1`, Class: "Mouse", Name: "Mouse compatible con HID", Enum: "HID", Container: "{aaaa}", Mfg: "Microsoft"},
		{Instance: `HID\VID_046D&PID_C539&MI_02\7&2`, Class: "HIDClass", Name: "Control de consumidor compatible con HID", Enum: "HID", Container: "{aaaa}"},
		{Instance: `USB\VID_046D&PID_C539\5&1`, Class: "USB", Name: "Dispositivo compuesto USB", BusDesc: "USB Receiver", Enum: "USB", Container: "{aaaa}", Mfg: "Logitech", DrvVer: "10.0.1"},
		{Instance: `BTHENUM\DEV_001122334455\8&1`, Class: "Bluetooth", Name: "WH-1000XM4", Enum: "BTHENUM", Container: "{bbbb}"},
		{Instance: `SWD\MMDEVAPI\{0.0.0.00000000}.{x}`, Class: "AudioEndpoint", Name: "Auriculares (WH-1000XM4)", Enum: "SWD", Container: "{bbbb}"},
		{Instance: `DISPLAY\DELA0B1\4&1`, Class: "Monitor", Name: "DELL P2422H", Enum: "DISPLAY", Container: "{cccc}"},
		{Instance: `PCI\VEN_8086&DEV_A0F0\3&1`, Class: "Net", Name: "Intel Wi-Fi 6 AX201", Enum: "PCI", Container: pcContainer, Problem: 10},
		{Instance: `USBSTOR\DISK&VEN_SANDISK\1`, Class: "DiskDrive", Name: "SanDisk Ultra USB Device", Enum: "USBSTOR", Container: "{dddd}", Problem: 43},
	}
	ext, in := GroupDevices(l)
	if len(ext) != 4 || len(in) != 1 {
		t.Fatalf("%d %d", len(ext), len(in))
	}
	m := map[string]DevGroup{}
	for _, g := range ext {
		m[g.ID] = g
	}
	if g := m["{aaaa}"]; g.Name != "USB Receiver" || g.Cat != "Ratones y punteros" || g.Conn != "USB" || g.VidPid != "046D:C539" || g.Mfg != "Logitech" {
		t.Errorf("ratón %+v", g)
	}
	if g := m["{bbbb}"]; g.Name != "WH-1000XM4" || g.Cat != "Auriculares y cascos" || g.Conn != "Bluetooth" {
		t.Errorf("cascos %+v", g)
	}
	if g := m["{cccc}"]; g.Cat != "Pantallas" || g.Conn != "Vídeo (HDMI / DisplayPort)" {
		t.Errorf("pantalla %+v", g)
	}
	if ext[0].ID != "{dddd}" || ext[0].Status != "problema" {
		t.Errorf("los que fallan van primero: %+v", ext[0])
	}
	if in[0].Status != "problema" || in[0].Cat != "Red" {
		t.Errorf("interno %+v", in[0])
	}
}
