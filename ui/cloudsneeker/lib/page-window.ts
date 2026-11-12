// Numbered pagination: which page numbers to show around the current page,
// with gaps for the rest ("1 … 4 5 6 … 16").

export const PAGE_GAP = "gap" as const;

export type PageWindowItem = number | typeof PAGE_GAP;

/** Pages to show: first, last, and `radius` pages each side of `page`. */
export const pageWindow = (
  page: number,
  pages: number,
  radius = 1,
): PageWindowItem[] => {
  if (pages <= 1) return pages === 1 ? [1] : [];
  // Few pages: show them all rather than a gap.
  if (pages <= radius * 2 + 5) {
    return Array.from({ length: pages }, (_, index) => index + 1);
  }
  const current = Math.min(Math.max(page, 1), pages);
  const shown = new Set<number>([1, pages]);
  for (let offset = -radius; offset <= radius; offset += 1) {
    const value = current + offset;
    if (value >= 1 && value <= pages) shown.add(value);
  }
  // Show a lone hidden page instead of a gap that hides only one number.
  const sorted = Array.from(shown).sort((left, right) => left - right);
  const items: PageWindowItem[] = [];
  sorted.forEach((value, index) => {
    const previous = sorted[index - 1];
    if (previous !== undefined && value - previous === 2) {
      items.push(previous + 1);
    } else if (previous !== undefined && value - previous > 2) {
      items.push(PAGE_GAP);
    }
    items.push(value);
  });
  return items;
};
