import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:usque/core/app_strings.dart';
import 'package:usque/models/app_models.dart';
import 'package:usque/screens/advanced_settings_screen.dart';
import 'package:usque/services/control_codec.dart';
import 'package:usque/services/engine_client.dart';
import 'package:usque/state/app_controller.dart';

import 'app_test.dart' show FakeEngineClient;
import 'congestion_control_test.dart' show codec, decodeProfile, response;
import 'ui_workflow_test.dart' show workflowHost;

void main() {
  test('TLS fingerprint survives JSON and protobuf and resets to default', () {
    for (final value in TlsFingerprint.values) {
      final profile = UsqueProfile.defaultProfile().copyWith(
        tlsFingerprint: value,
      );
      expect(profile.toMap()['tls_fingerprint'], value.wireName);
      expect(UsqueProfile.fromMap(profile.toMap()).tlsFingerprint, value);
      expect(decodeProfile(codec.encodeProfile(profile)).tlsFingerprint, value);
      expect(
        profile.resetAdvancedDefaults().tlsFingerprint,
        TlsFingerprint.defaultProfile,
      );
    }
    final legacy = UsqueProfile.defaultProfile().toMap()
      ..remove('tls_fingerprint');
    expect(
      UsqueProfile.fromMap(legacy).tlsFingerprint,
      TlsFingerprint.defaultProfile,
    );
    expect(
      decodeProfile(Uint8List(0)).tlsFingerprint,
      TlsFingerprint.defaultProfile,
    );
    for (final value in [0, 1, 2]) {
      final payload = (ControlPayloadWriter()..enumeration(26, value))
          .takeBytes();
      expect(
        decodeProfile(payload).tlsFingerprint,
        value == 2 ? TlsFingerprint.chrome131 : TlsFingerprint.defaultProfile,
      );
    }
    for (final value in ['chrome', 'Chrome131', 'defaultProfile', null, 2]) {
      expect(
        () => UsqueProfile.fromMap({...legacy, 'tls_fingerprint': value}),
        throwsFormatException,
      );
    }
    expect(
      () => decodeProfile(
        (ControlPayloadWriter()..enumeration(26, 99)).takeBytes(),
      ),
      throwsA(isA<EngineException>()),
    );
  });

  test(
    'capabilities decode known packed and unpacked values, legacy is empty',
    () {
      final packed =
          (ControlPayloadWriter()
                ..message(48, Uint8List.fromList([1, 2, 2, 99])))
              .takeBytes();
      final unpacked =
          (ControlPayloadWriter()
                ..enumeration(48, 1)
                ..enumeration(48, 2))
              .takeBytes();
      for (final payload in [packed, unpacked]) {
        expect(
          codec
              .decodeResponse(response(15, payload), 'cc')
              .capabilities!
              .tlsFingerprints,
          TlsFingerprint.values,
        );
      }
      expect(
        codec
            .decodeResponse(response(15, Uint8List(0)), 'cc')
            .capabilities!
            .tlsFingerprints,
        isEmpty,
      );
      expect(
        EngineCapabilities.fromMap({
          'tls_fingerprints': ['default', 'chrome131', 'future'],
        }).tlsFingerprints,
        TlsFingerprint.values,
      );
      expect(
        const EngineCapabilities(),
        isNot(const EngineCapabilities(tlsFingerprints: TlsFingerprint.values)),
      );
    },
  );

  test('fingerprint-only edit has its own shared network field', () {
    final profile = UsqueProfile.defaultProfile();
    expect(
      networkSettingsChangedFields(
        profile,
        profile.copyWith(tlsFingerprint: TlsFingerprint.chrome131),
      ),
      ['tls_fingerprint'],
    );
    expect(AppStrings.debugCatalogsAreComplete, isTrue);
    expect(AppStrings.debugUntranslatedFeatureKeys(), isEmpty);
  });

  Future<AppController> screen(
    WidgetTester tester, {
    bool supported = true,
    TlsFingerprint value = TlsFingerprint.defaultProfile,
    double scale = 1,
    LocalePreference locale = LocalePreference.english,
  }) async {
    tester.view.physicalSize = const Size(430, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final engine = FakeEngineClient()
      ..storedProfiles = [
        UsqueProfile.defaultProfile().copyWith(tlsFingerprint: value),
      ];
    final app = AppController(engine)
      ..localePreference = locale
      ..engineCapabilities = EngineCapabilities(
        automaticEndpoints: true,
        networkSettingsApplication: true,
        tlsFingerprints: supported ? TlsFingerprint.values : const [],
      );
    app.sharedNetwork = app.sharedNetwork.copyWith(tlsFingerprint: value);
    expect(app.activeProfile.tlsFingerprint, value);
    addTearDown(app.dispose);
    await tester.pumpWidget(
      workflowHost(
        app,
        scale: scale,
        home: AdvancedSettingsScreen(controller: app),
      ),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(
      find.byType(DropdownButtonFormField<TlsFingerprint>),
    );
    await tester.pumpAndSettle();
    return app;
  }

  testWidgets(
    'Chrome choice stays a draft until apply and uses exact field mask',
    (tester) async {
      final app = await screen(tester);
      await tester.tap(find.byType(DropdownButtonFormField<TlsFingerprint>));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Chrome 131').last);
      await tester.pumpAndSettle();
      expect(app.sharedNetwork.tlsFingerprint, TlsFingerprint.defaultProfile);
      await tester.tap(find.widgetWithText(FilledButton, 'Apply changes'));
      await tester.pumpAndSettle();
      expect(app.sharedNetwork.tlsFingerprint, TlsFingerprint.chrome131);
      expect(app.networkSettings.state?.deferredFields, ['tls_fingerprint']);
    },
  );

  testWidgets(
    'older engine preserves stored Chrome and blocks unsupported save',
    (tester) async {
      final app = await screen(
        tester,
        supported: false,
        value: TlsFingerprint.chrome131,
      );
      final field = tester.widget<DropdownButtonFormField<TlsFingerprint>>(
        find.byType(DropdownButtonFormField<TlsFingerprint>),
      );
      expect(field.onChanged, isNull);
      expect(field.initialValue, TlsFingerprint.chrome131);
      expect(
        await app.saveNetwork(app.activeProfile.copyWith(mtu: 1300)),
        isFalse,
      );
      expect(app.sharedNetwork.tlsFingerprint, TlsFingerprint.chrome131);
      expect(app.lastError, app.strings.get('tls_fingerprint_unsupported'));
    },
  );

  testWidgets(
    'Chinese fingerprint picker fits narrow layout at 200 percent text',
    (tester) async {
      await screen(
        tester,
        scale: 2,
        locale: LocalePreference.simplifiedChinese,
      );
      expect(find.text('TLS 指纹'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.tap(find.byType(DropdownButtonFormField<TlsFingerprint>));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Chrome 131').last);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );
}
