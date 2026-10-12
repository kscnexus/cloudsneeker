export const BRAND_RESOURCE_TYPE = "cloudsneeker-brand" as const;

export interface BrandAttributes {
  name: string;
  short_name: string;
  vendor: string;
  tagline: string;
  website_url: string;
  docs_url: string;
  support_url: string;
  status_url: string;
  terms_url: string;
  privacy_url: string;
  logo_url: string;
}

export interface BrandResource {
  type: typeof BRAND_RESOURCE_TYPE;
  id: string;
  attributes: BrandAttributes;
}

export interface BrandResponse {
  data: BrandResource;
}
