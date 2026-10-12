import { Info } from "lucide-react";
import { Suspense } from "react";

import { getBrand } from "@/cloudsneeker/actions/brand";
import { BRAND } from "@/cloudsneeker/brand";
import { AboutCard } from "@/cloudsneeker/components/about-card";
import { Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default function AboutPage() {
  return (
    <ContentLayout title={`About ${BRAND.name}`} icon={<Info />}>
      <Suspense fallback={<Skeleton className="h-40 w-full rounded-xl" />}>
        <SSRAboutCard />
      </Suspense>
    </ContentLayout>
  );
}

const SSRAboutCard = async () => {
  const brand = await getBrand();

  return <AboutCard attributes={brand?.data.attributes} />;
};
