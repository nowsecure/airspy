export interface IConfig {
    targetDevice: TargetDevice;
}

export type TargetDevice = ITargetDeviceLocal | ITargetDeviceUsb | ITargetDeviceRemote | ITargetDeviceById;

export interface ITargetDeviceLocal {
    kind: "local";
}

export interface ITargetDeviceUsb {
    kind: "usb";
}

export interface ITargetDeviceRemote {
    kind: "remote";
}

export interface ITargetDeviceById {
    kind: "by-id";
    id: string;
}