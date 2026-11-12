import type { LinkingOptions } from '@react-navigation/native';

// shopmate://product/123, shopmate://portal?url=..., shopmate://oauth
export const linking: LinkingOptions<any> = {
  prefixes: ['shopmate://'],
  config: {
    screens: {
      Home: '',
      Product: 'product/:id',
      WebPortal: 'portal',
      OAuthCallback: 'oauth',
    },
  },
};
