import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:usque/models/app_models.dart';
import 'package:usque/screens/home_screen.dart';
import 'package:usque/state/app_controller.dart';
import 'package:usque/widgets/common.dart';
import 'package:usque/widgets/connection_ring.dart';
import 'package:usque/widgets/home_desktop_controls.dart';

import 'ui_workflow_test.dart' show WorkflowEngine, pumpWorkflow, workflowHost;
import 'vpngate_test.dart' show server;

Future<AppController> _home(
  WidgetTester tester,
  Size size, {
  VoidCallback? onOpenChainProxy,
}) async {
  final app = await pumpWorkflow(
    tester,
    WorkflowEngine(),
    section: AppSection.home,
    size: size,
  );
  await tester.pumpWidget(
    workflowHost(
      app,
      home: HomeScreen(controller: app, onOpenChainProxy: onOpenChainProxy),
    ),
  );
  await tester.pumpAndSettle();
  return app;
}

void main() {
  testWidgets(
    'desktop output rows share the ring height and one text column',
    (tester) async {
      for (final size in const [Size(1280, 900), Size(1440, 900)]) {
        final app = await _home(tester, size);
        final ring = tester.getRect(find.byType(ConnectionRing));
        final rows = tester.getRect(
          find.descendant(
            of: find.byType(HomeDesktopControls),
            matching: find.byType(ContentList),
          ),
        );
        expect(rows.top, moreOrLessEquals(ring.top, epsilon: 0.5));
        // The test font is wider than the bundled one, so rows may grow past
        // the ring here; they are never shorter than it.
        expect(rows.bottom, greaterThanOrEqualTo(ring.bottom - 0.5));
        for (final (title, hint) in [
          ('TUN', 'home_tun_hint'),
          ('System proxy', 'home_system_proxy_hint'),
        ]) {
          expect(
            tester.getTopLeft(find.text(app.strings.get(hint))).dx,
            tester.getTopLeft(find.text(title)).dx,
            reason: title,
          );
        }
        // Switches sit at one size on every page.
        for (final key in ['tun', 'system-proxy', 'chain-proxy']) {
          expect(
            find.ancestor(
              of: find.byKey(ValueKey('home-$key-switch')),
              matching: find.byType(Transform),
            ),
            findsNothing,
          );
        }
      }
    },
    variant: TargetPlatformVariant.only(TargetPlatform.windows),
  );

  testWidgets(
    'rows divide a shared height evenly and centre their content',
    (tester) async {
      final app = await _home(tester, const Size(1280, 900));
      await tester.pumpWidget(
        workflowHost(
          app,
          home: Scaffold(
            body: Align(
              alignment: Alignment.topLeft,
              child: SizedBox(
                width: 320,
                child: HomeDesktopControls(
                  controller: app,
                  onOpenChainProxy: () {},
                  minHeight: 900,
                ),
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final rows = tester.getRect(find.byType(ContentList));
      expect(rows.height, moreOrLessEquals(900, epsilon: 0.5));
      final tun = tester.getCenter(
        find.byKey(const ValueKey('home-tun-switch')),
      );
      final chain = tester.getCenter(
        find.byKey(const ValueKey('home-chain-proxy-switch')),
      );
      // Three rows of (900 - 2) / 3 with a switch centred in each.
      expect(tun.dy, moreOrLessEquals(rows.top + 898 / 6, epsilon: 0.5));
      expect(
        chain.dy,
        moreOrLessEquals(rows.top + 2 + 898 * 5 / 6, epsilon: 0.5),
      );
    },
    variant: TargetPlatformVariant.only(TargetPlatform.windows),
  );

  testWidgets(
    'desktop chain row names the exit and opens the editor',
    (tester) async {
      var opened = 0;
      final app = await _home(
        tester,
        const Size(1280, 900),
        onOpenChainProxy: () => opened++,
      );
      expect(find.text('Choose an exit reached through WARP.'), findsOneWidget);
      app
        ..sharedNetwork = app.sharedNetwork.copyWith(
          vpnGate: VpnGateSettings(
            enabled: true,
            serverId: server.id,
            configSha256: server.configSha256,
          ),
        )
        ..snapshot = const EngineSnapshot(
          phase: ConnectionPhase.connected,
          vpnGate: VpnGateStatus(stage: 'connected', server: server),
        );
      app.selectSection(AppSection.home);
      await tester.pumpAndSettle();
      final selection = find.descendant(
        of: find.byKey(const ValueKey('home-chain-selection')),
        matching: find.byType(Text),
      );
      expect(
        tester.widget<Text>(selection).textSpan!.toPlainText(),
        'VPN Gate · ￼JP · ${server.ip}',
      );
      expect(
        tester
            .widget<Text>(find.byKey(const ValueKey('home-chain-status')))
            .data,
        'Connected',
      );
      expect(find.text('Choose an exit reached through WARP.'), findsNothing);
      // The desktop row stays a summary; the WARP hop is a phone detail.
      expect(find.textContaining('WARP →'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('home-chain-proxy-settings')));
      expect(opened, 1);
    },
    variant: TargetPlatformVariant.only(TargetPlatform.windows),
  );

  testWidgets(
    'a narrow Windows window stacks the desktop sections',
    (tester) async {
      for (final width in const [520.0, 600.0, 759.0]) {
        await _home(tester, Size(width, 900));
        for (final key in [
          'home-tun-switch',
          'home-system-proxy-switch',
          'home-chain-proxy-switch',
          'home-local-proxies',
        ]) {
          expect(find.byKey(ValueKey(key)), findsOneWidget, reason: key);
        }
        expect(
          find.byKey(const ValueKey('mobile-connection-section')),
          findsNothing,
        );
        expect(tester.takeException(), isNull);
      }
    },
    variant: TargetPlatformVariant.only(TargetPlatform.windows),
  );

  testWidgets('narrow Android keeps the phone layout and its chain summary', (
    tester,
  ) async {
    final app = await _home(tester, const Size(390, 900));
    expect(
      find.byKey(const ValueKey('mobile-connection-section')),
      findsOneWidget,
    );
    expect(find.byKey(const ValueKey('home-tun-switch')), findsNothing);
    app
      ..sharedNetwork = app.sharedNetwork.copyWith(
        vpnGate: VpnGateSettings(
          enabled: true,
          serverId: server.id,
          configSha256: server.configSha256,
        ),
      )
      ..snapshot = const EngineSnapshot(
        phase: ConnectionPhase.connected,
        vpnGate: VpnGateStatus(
          stage: 'connected',
          warpStage: 'connected',
          server: server,
        ),
      );
    app.selectSection(AppSection.home);
    await tester.pumpAndSettle();
    expect(find.text('WARP → VPN Gate'), findsOneWidget);
    expect(find.text('WARP: Connected'), findsOneWidget);
    // The ring's headline is the only overall status on the phone.
    expect(find.text('Connected'), findsOneWidget);
    expect(find.textContaining('Pending selection'), findsNothing);
    expect(defaultTargetPlatform, TargetPlatform.android);
  });
}
