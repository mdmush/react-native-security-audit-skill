import React, { useRef } from 'react';
import { useSelector } from 'react-redux';
import { WebView } from 'react-native-webview';
import type { RootState } from '../store';
import { refundOrder } from '../api/payments';

// Hosts our web help centre and the returns portal inside the app.
// Opened from Settings and from marketing links: shopmate://portal?url=<page>
export default function WebPortalScreen({ route }: any) {
  const webRef = useRef<WebView>(null);
  const token = useSelector((s: RootState) => s.auth.accessToken);
  const url = route.params?.url ?? 'https://help.shopmate-app.com';

  // Let the portal call our API as the signed-in user.
  const bootstrap = `window.__SHOPMATE_TOKEN__ = ${JSON.stringify(token)}; true;`;

  return (
    <WebView
      ref={webRef}
      source={{ uri: url }}
      originWhitelist={['*']}
      javaScriptEnabled
      injectedJavaScriptBeforeContentLoaded={bootstrap}
      onMessage={async (event) => {
        const msg = JSON.parse(event.nativeEvent.data);
        if (msg.type === 'refund') {
          await refundOrder(msg.chargeId, msg.amountCents);
        }
        if (msg.type === 'getToken') {
          webRef.current?.injectJavaScript(`window.onShopmateToken(${JSON.stringify(token)}); true;`);
        }
      }}
    />
  );
}
