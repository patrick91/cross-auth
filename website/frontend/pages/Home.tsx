import { HomePage, HomeHeader, HomeHero, HomeFeatures, HomeCTA, HomeFooter, type HomeFeature } from '@usecross/docs'

interface HomeProps {
  title: string
  tagline: string
  description: string
  installCommand: string
  ctaText: string
  ctaHref: string
  features: HomeFeature[]
  logoUrl?: string
  heroLogoUrl?: string
  footerLogoUrl?: string
  githubUrl?: string
  navLinks?: Array<{ label: string; href: string }>
}

export default function Home(props: HomeProps) {
  const navLinks = props.navLinks ?? [{ label: 'Docs', href: '/docs' }]

  return (
    <HomePage {...props} navLinks={navLinks}>
      <HomeHeader />
      <HomeHero />
      <HomeFeatures />
      <HomeCTA />
      <HomeFooter />
    </HomePage>
  )
}
