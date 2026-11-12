package com.shopmate

import android.app.Application
import com.facebook.react.ReactApplication
import com.facebook.react.modules.network.OkHttpClientProvider
import com.facebook.soloader.SoLoader
import com.shopmate.network.StagingHttpClientFactory

class MainApplication : Application(), ReactApplication {

    override fun onCreate() {
        super.onCreate()
        SoLoader.init(this, false)
        // Needed for staging login, see StagingHttpClientFactory
        OkHttpClientProvider.setOkHttpClientFactory(StagingHttpClientFactory())
    }
}
