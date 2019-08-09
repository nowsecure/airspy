import { IHTTPHeader } from "./interfaces";

export class HTTPServerRequest {
    private static apiSpec: IApiSpec = {
        name: "HTTPServerRequest",
        visibility: "private",
        methods: {
            copyProperty: ["object:owned", ["pointer", "pointer"]],
        },
        constants: [
            "Method",
            "Path",
            "Headers",
            "HeaderOrderKey",
            "HeaderValuesKey",
        ]
    };

    public handle: NativePointer;

    private api: {
        kMethod: NativePointer;
        kPath: NativePointer;
        kHeaders: NativePointer;
        kHeaderOrderKey: NativePointer;
        kHeaderValuesKey: NativePointer;

        copyProperty(request: NativePointerValue, property: NativePointerValue): ObjC.Object;
    };

    private constructor(handle: NativePointer) {
        this.handle = handle;
        this.api = importApi(HTTPServerRequest.apiSpec);
    }

    public static fromHandle(handle: NativePointer): HTTPServerRequest {
        return new HTTPServerRequest(handle);
    }

    get method(): string {
        const { api } = this;

        return api.copyProperty(this.handle, api.kMethod).toString();
    }

    get path(): string {
        const { api } = this;

        return api.copyProperty(this.handle, api.kPath).toString();
    }

    get headers(): IHTTPHeader[] {
        const result: IHTTPHeader[] = [];

        const { api } = this;

        const headers = api.copyProperty(this.handle, api.kHeaders);

        const keys = headers.objectForKey_(api.kHeaderOrderKey);
        const values = headers.objectForKey_(api.kHeaderValuesKey);

        const count = keys.count().valueOf();
        for (let i = 0; i !== count; i++) {
            const key = keys.objectAtIndex_(i);
            const value = values.objectForKey_(key);
            result.push({
                name: key.toString(),
                value: value.toString()
            });
        }

        return result;
    }
}

export class HTTPServerResponse {
    private static apiSpec: IApiSpec = {
        name: "HTTPServerResponse",
        visibility: "private",
        methods: {
            copyProperty: ["object:owned", ["pointer", "pointer"]],
        },
        constants: [
            "Message",
        ]
    };

    public handle: NativePointer;

    private api: {
        kMessage: NativePointer;

        copyProperty(response: NativePointerValue, property: NativePointerValue): ObjC.Object;
    };

    private constructor(handle: NativePointer) {
        this.handle = handle;
        this.api = importApi(HTTPServerResponse.apiSpec);
    }

    public static fromHandle(handle: NativePointer): HTTPServerResponse {
        return new HTTPServerResponse(handle);
    }

    get message(): HTTPMessage {
        const { api } = this;

        return HTTPMessage.fromHandle(api.copyProperty(this.handle, api.kMessage).handle);
    }
}

export class HTTPMessage {
    private static apiSpec: IApiSpec = {
        name: "HTTPMessage",
        visibility: "public",
        methods: {
            copyResponseStatusLine: ["object:owned", ["pointer"]],
            copyAllHeaderFields: ["object:owned", ["pointer"]],
            copyBody: ["object:owned", ["pointer"]],
        },
        constants: []
    };

    public handle: NativePointer;

    private api: {
        copyResponseStatusLine(message: NativePointerValue): ObjC.Object;
        copyAllHeaderFields(message: NativePointerValue): ObjC.Object;
        copyBody(message: NativePointerValue): ObjC.Object | null;
    };

    private constructor(handle: NativePointer) {
        this.handle = handle;
        this.api = importApi(HTTPMessage.apiSpec);
    }

    public static fromHandle(handle: NativePointer): HTTPMessage {
        return new HTTPMessage(handle);
    }

    get responseStatusLine(): string {
        return this.api.copyResponseStatusLine(this.handle).toString();
    }

    get headers(): IHTTPHeader[] {
        const result: IHTTPHeader[] = [];

        const fields = this.api.copyAllHeaderFields(this.handle);

        const enumerator = fields.keyEnumerator();
        let key: ObjC.Object;
        while ((key = enumerator.nextObject()) !== null) {
            const value = fields.objectForKey_(key);
            result.push({
                name: key.toString(),
                value: value.toString()
            });
        }

        return result;
    }

    get body(): ObjC.Object | null {
        return this.api.copyBody(this.handle);
    }
}

interface IApiSpec {
    name: string;
    visibility: "public" | "private";
    methods: {
        [name: string]: [NativeType | "object:owned", NativeType[]];
    };
    constants: string[];
}

const cachedApis = new Map<string, any>();

function importApi<T>(spec: IApiSpec): T {
    const apiName = spec.name;

    let api = cachedApis.get(apiName);
    if (api === undefined) {
        api = {};

        const className = spec.name;
        const { methods, constants } = spec;

        const visibilityPrefix = (spec.visibility === "private") ? "_" : "";
        const cMethodPrefix = [visibilityPrefix, "CF", className].join("");
        const cConstantPrefix = [visibilityPrefix, "kCF", className].join("");

        Object.keys(methods)
            .forEach(methodName => {
                const [returnType, argumentTypes] = methods[methodName];

                const exportName = [cMethodPrefix, methodName[0].toUpperCase(), methodName.substr(1)].join("");
                const rawReturnType = (returnType.indexOf("object:") === 0) ? "pointer" : returnType;
                const impl = new NativeFunction(Module.getExportByName("CFNetwork", exportName), rawReturnType, argumentTypes);

                if (returnType === "object:owned") {
                    api[methodName] = (...args: any[]): ObjC.Object | null => {
                        const handle = impl.apply(impl, args) as NativePointer;
                        if (handle.isNull()) {
                            return null;
                        }

                        return new ObjC.Object(handle).autorelease();
                    };
                } else {
                    api[methodName] = impl;
                }
            });

        constants
            .forEach(constantName => {
                const exportName = cConstantPrefix + constantName;
                api[`k${constantName}`] = Module.getExportByName("CFNetwork", exportName).readPointer();
            });

        cachedApis.set(apiName, api);
    }

    return api;
}