# Compiling

Requires JDK 17 (11 will not work) and the Android SDK with platform 35.

```sh
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.example.keymastertest/.MainActivity
```

The first build downloads the Android Gradle Plugin and takes a few minutes; later builds take
seconds. If security software blocks the Gradle daemon, add `--no-daemon`.
