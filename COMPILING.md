# Compiling

Requires JDK 17 (11 will not work) and the Android SDK with platform 35.

```sh
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n io.github.nezjusz.keymastertest/.MainActivity
```

The first build downloads the Android Gradle Plugin and takes a few minutes; later builds take
seconds. If security software blocks the Gradle daemon, add `--no-daemon`.

## Continuous integration

`.github/workflows/android.yml` runs on every push to `main` and on every pull request. Those runs
**only verify**: they run the unit tests, lint, and assembly against the repository exactly as it
stands, and publish nothing. If any of the three fails the run goes red, and no APK is produced.

## Cutting a release

Releases are only ever published by hand. Go to the Actions tab, choose **Android CI**, click
**Run workflow**, and type the version you want, for example `1.2.0`.

That run:

- builds and tests the same way a push does, but stamps the version you typed onto the APK
- attaches the APK to the run's summary page
- creates a GitHub release tagged `v1.2.0` with the APK attached and generated release notes

`versionName` comes from your input, so you never have to edit `app/build.gradle` to publish.
`versionCode` is the workflow run number, which keeps every published APK unique and increasing
without anyone having to remember to bump it.

The version is checked before use: only plain dotted numbers are accepted, so a stray `v` prefix,
a pre-release suffix, or anything containing a slash is rejected instead of becoming a broken tag.
Re-running a workflow for a version that already has a release fails deliberately, because
republishing a version should be an explicit decision.

To build a specific version locally, override it on the command line:

```sh
./gradlew assembleDebug -PreleaseVersionName=1.2.0 -PreleaseVersionCode=42
```

The published APK is the debug build, so it is signed with the debug keystore and installs with
`adb install`. Signing a release build would mean committing a keystore or wiring one in as a
secret, which this project deliberately does not do.
