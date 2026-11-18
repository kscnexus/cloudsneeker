/** `1 finding` / `3 findings`: a count with the right noun form. */
export const countNoun = (
  count: number,
  singular: string,
  plural = `${singular}s`,
): string =>
  `${count.toLocaleString("en-US")} ${count === 1 ? singular : plural}`;
