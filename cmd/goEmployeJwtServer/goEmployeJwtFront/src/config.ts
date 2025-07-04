import { levelLog, Log } from "@/log"

export const DEV = process.env.NODE_ENV === "development"
export const HOME = DEV ? "http://localhost:3000/" : "/"
const url = new URL(location.toString())
export const BACKEND_URL = DEV ? "http://localhost:8787" : url.origin
export const getLog = (ModuleName: string, verbosityDev: levelLog, verbosityProd: levelLog) =>
  DEV ? new Log(ModuleName, verbosityDev) : new Log(ModuleName, verbosityProd)

export const defaultAxiosTimeout = 10000 // 10 sec
