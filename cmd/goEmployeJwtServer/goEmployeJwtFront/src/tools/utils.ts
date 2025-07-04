/*eslint @typescript-eslint/no-explicit-any: "off"*/
import { getLog } from "@/config";

const log = getLog("Utils", 2, 2);
/**
 * check if the given variable is null or undefined
 * @param variable
 * @returns true if given variable is null or undefined, false in other cases
 */
export const isNullOrUndefined = (variable: any): boolean =>
  typeof variable === "undefined" || variable === null;

/**
 * check if the given variable is null, undefined or an empty string(zero length)
 * @param variable
 * @returns true if given variable is null or undefined or an empty string, false in other cases
 */
export const isEmpty = (variable: any): boolean =>
  typeof variable === "undefined" || variable === null || variable === "";

/**
 * convert a date string from french europe dd-mm-yyyy to iso yyyy-mm-dd
 * @param frDate string dd-mm-yyyy
 * @returns date as string in format yyyy-mm-dd
 */
export const dateFr2Iso = function (frDate: string): string {
  if (isEmpty(frDate)) {
    return "";
  }
  let separator = "."
  if (frDate.includes("-")){
    separator = "-"
  }
  const  [d, m, y]= frDate.split(separator);
  return [y, m, d].join("-");
};

/**
 * convert a date string from french europe dd-mm-yyyy to timestamp
 * @param frDate  Parse DD.MM.YYYY date format
 */
export const getTimeStampFromFrDate = (frDate: string): string => {
  log.t(`#> entering : ${frDate}`);

      let parsedDate: string;
      if (frDate) {
        let separator = "."
        if (frDate.includes("-")){
          separator = "-"
        }
        const [day, month, year] = frDate.split(separator);
        if (day && month && year) {
          // Create a Date object (month is 0-based in JavaScript, so subtract 1)
          const date = new Date(Number(year), Number(month) - 1, Number(day));
          if (isNaN(date.getTime())) {
            throw new Error(`Invalid date format for frDate: ${frDate}`);
          }
          parsedDate = date.toISOString();
        } else {
          parsedDate = new Date().toISOString(); // Fallback to current date
        }
      } else {
        parsedDate = new Date().toISOString(); // Fallback to current date
      }
  return parsedDate;
};




/**
 * convert a date string from iso yyyy-mm-dd in french europe dd-mm-yyyy
 * @param strIsoDate string yyyy-mm-dd
 * @returns date as string in format dd-mm-yyyy
 */
export const dateIso2Fr = function (strIsoDate: string): string {
  if (isEmpty(strIsoDate)) {
    return "";
  }
  const [y, m, d] = strIsoDate.split("-");
  return [d, m, y].join("-");
};

export const getDateFromTimeStamp = (isoDate: string) => {
  log.t(`#> entering : ${isoDate}`, isoDate);
  if (typeof isoDate !== "string") return "not_date";
  if (isNullOrUndefined(isoDate) || isoDate.indexOf("T") < 0) return "";
  const dateTS = dateIso2Fr(isoDate.split("T")[0]);
  log.l(`dateTS : ${dateTS}`, isoDate);
  return dateTS;
};

export const getDateIsoFromTimeStamp = (isoDate: string): string => {
  log.t(`#> entering : ${isoDate}`, isoDate);
  if (typeof isoDate !== "string") return "not_date";
  if (isNullOrUndefined(isoDate)) return "";
  if (isoDate.indexOf("T") > 0) return isoDate.split("T")[0];
  if (isoDate.indexOf(" ") > 0) return isoDate.split(" ")[0];
  return "not_timestamp";
};

export const isTimestamp = (str: string): boolean => {
  const date = new Date(str);
  return !isNaN(date.getTime());
};

export const truncateText = (text: string, maxSize = 40): string => {
  if (isNullOrUndefined(text)) return "";
  if (text.length < maxSize) return text;
  return `${text.substring(0, maxSize)}…`;
};

export const parseJsonWithDetailedError = (
  jsonString: string,
  context: number = 100,
): any => {
  log.t(">parseJsonWithDetailedError ");
  try {
    // Attempt to parse the JSON string
    const result = JSON.parse(jsonString);
    log.l("Parsing successful", result);
    return result;
  } catch (error) {
    if (error instanceof SyntaxError) {
      // Extracting approximate position information from the error message
      const match = error.message.match(/position (\d+)/);
      if (match) {
        const position = parseInt(match[1], 10);
        // Calculating line and column based on the position
        const lines = jsonString.substring(0, position).split("\n");
        const line = lines.length;
        const column = lines[lines.length - 1].length + 1;
        // Extracting a 30-character excerpt around the error position
        const start = Math.max(0, position - context);
        const end = Math.min(jsonString.length, position + context);
        const excerpt = `...${jsonString.slice(start, position)}«${jsonString.charAt(position)}»${jsonString.substring(position + 1, end)}...`;

        log.w(
          `Error parsing JSON at [${line}:${column}] ${error.message}: "${excerpt}"`,
        );
        log.l(jsonString);
      } else {
        log.w("Error parsing JSON:", error.message);
      }
    } else {
      // Non-syntax errors (unlikely in this context, but good practice to handle)
      log.w("Unexpected error:", error);
    }
  }
};

export const escapeJsonString = (str: string): string => {
  log.t(`in escapeJsonString str:${str}`);
  return str
    .replace(/\\n/g, "\\n")
    .replace(/\\'/g, "\\'")
    .replace(/\\"/g, '\\"')
    .replace(/\\&/g, "\\&")
    .replace(/\\r/g, "\\r")
    .replace(/\\t/g, "\\t")
    .replace(/\\b/g, "\\b")
    .replace(/\\f/g, "\\f")
    .replace(/[\u0000-\u0019]+/g, "")
    .replace(/"/g, "");
};

export const extractFirstMatch = (str: string, regex: RegExp): string => {
  log.t(`in extractFirstMatch(str:${str}, regex:${regex})`);
  const match = regex.exec(str);
  return isNullOrUndefined(match) ? "" : (match?.[1] ?? "");
};

export const getDistinctValues = (arr: any[]): any[] => {
  log.t(`in getDistinctValues(arr:${arr})`);
  return [...new Set(arr)];
};

export const getDistinctValuesFromKey = (arr: any[], key: string): any[] => {
  log.t(`in getDistinctValuesFromKey(arr:${arr}, key:${key})`);
  return getDistinctValues(arr.map((item) => item[key]));
};

export const doesFileExist = (url: string): boolean => {
  log.t(`in doesFileExist(url:${url})`);
  let http = new XMLHttpRequest();
  http.open("HEAD", url, false);
  http.send();
  return http.status == 200;
};

