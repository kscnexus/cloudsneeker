/**
 * Short label for the viewer's time zone at `date`, such as "IST",
 * "GMT+5:30", or "UTC". Upstream took the first three letters of the IANA
 * city, which turned "Asia/Calcutta" into "CAL".
 */
export const localTimeZoneLabel = (date: Date): string => {
  try {
    const part = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" })
      .formatToParts(date)
      .find((item) => item.type === "timeZoneName");
    return part?.value ?? "";
  } catch {
    return "";
  }
};
