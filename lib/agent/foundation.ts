export function parseNSData(data: ObjC.Object | null): ArrayBuffer | null {
    return (data !== null) ? data.bytes().readByteArray(data.length()) : null;
}
