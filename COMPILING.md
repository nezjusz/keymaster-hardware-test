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

`.github/workflows/android.yml` runs on every push to `main`, on every pull request, and on demand
from the Actions tab. It runs the unit tests, lint, and assembly, and the job only goes green if
all three pass, so a broken build cannot produce a published APK.

Every run uploads the debug APK as a workflow artifact named
`keymaster-hardware-test-<commit>`, downloadable from the run's summary page for 30 days.

## Cutting a release

Push a `v`-prefixed tag and the same workflow attaches the APK to a GitHub release:

```sh
git tag v1.1.0
git push origin v1.1.0
```

The release job refuses to publish if the tag does not match `versionName` in `app/build.gradle`,
which catches the common mistake of tagging a version you forgot to bump. Release notes are
generated from the commits.

The published APK is the debug build, so it is signed with the debug keystore and installs with
`adb install`. Signing a release build would mean committing a keystore or wiring one in as a
secret, which this project deliberately does not do.
