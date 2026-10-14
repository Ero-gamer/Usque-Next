import 'package:flutter_test/flutter_test.dart';
import 'package:usque/core/app_strings.dart';
import 'package:usque/core/chain_exit_presentation.dart';
import 'package:usque/models/app_models.dart';
import 'package:usque/widgets/common.dart' show StatusTone;

import 'chain_proxy_test.dart' show imported;
import 'vpngate_test.dart' show server;

UsqueProfile _profile({
  bool enabled = false,
  ChainSource source = ChainSource.openvpnCustom,
  String? profileId,
  bool gateSelection = false,
}) {
  final base = UsqueProfile.defaultProfile();
  return source == ChainSource.vpnGate
      ? base.copyWith(
          vpnGate: VpnGateSettings(
            enabled: enabled,
            serverId: gateSelection ? server.id : '',
            configSha256: gateSelection ? server.configSha256 : '',
          ),
          chainExit: ChainExitSettings(enabled: enabled, source: source),
        )
      : base.copyWith(
          chainExit: ChainExitSettings(
            enabled: enabled,
            source: source,
            profileId: profileId,
            revision: profileId == null ? null : 'r1',
          ),
        );
}

void main() {
  final strings = AppStrings(LocalePreference.english);

  test('an idle chain without a choice is not enabled and names no exit', () {
    final view = ChainExitPresentation.of(
      profile: _profile(),
      snapshot: const EngineSnapshot(),
    );
    expect(view.statusLabel(strings), 'Not enabled');
    expect(view.selection, isNull);
    expect(view.savedKey, isNull);
    expect(view.live, isFalse);
  });

  test('saved choices are looked up by source and fall back readably', () {
    final gate = ChainExitPresentation.of(
      profile: _profile(
        enabled: true,
        source: ChainSource.vpnGate,
        gateSelection: true,
      ),
      snapshot: const EngineSnapshot(),
    );
    expect(gate.statusLabel(strings), 'Enabled · not connected');
    expect(gate.savedKey, 'vpn_gate:${server.id}:${server.configSha256}');
    expect(gate.selection?.id, server.id);
    final resolved = gate.withSaved(const ChainSelection(server: server));
    expect(resolved.selection?.server, server);

    final custom = ChainExitPresentation.of(
      profile: _profile(
        source: ChainSource.wireguardCustom,
        profileId: imported.id,
      ),
      snapshot: const EngineSnapshot(),
    );
    expect(custom.savedKey, 'wireguard_custom:${imported.id}:r1');
    // A configuration has no readable fallback before its name resolves.
    expect(custom.selection, isNull);
    expect(
      custom.withSaved(ChainSelection(name: imported.name)).selection?.name,
      imported.name,
    );
  });

  test('live sessions win over saved choices and follow the home status', () {
    final profile = _profile(
      enabled: true,
      source: ChainSource.vpnGate,
      gateSelection: true,
    );
    for (final (phase, stage, label, tone) in [
      (
        ConnectionPhase.preparing,
        'connecting_server',
        'Connecting',
        StatusTone.brand,
      ),
      (ConnectionPhase.connected, 'connected', 'Connected', StatusTone.success),
      (ConnectionPhase.error, 'error', 'Connection failed', StatusTone.danger),
      (
        ConnectionPhase.disconnecting,
        'connected',
        'Disconnecting',
        StatusTone.neutral,
      ),
    ]) {
      final view = ChainExitPresentation.of(
        profile: profile,
        snapshot: EngineSnapshot(
          phase: phase,
          vpnGate: VpnGateStatus(stage: stage, server: server),
        ),
      );
      expect(view.statusLabel(strings), label, reason: '$phase $stage');
      expect(view.tone, tone, reason: '$phase $stage');
      expect(view.live, isTrue);
      expect(view.savedKey, isNull);
      expect(view.selection?.server, server);
      expect(view.withSaved(const ChainSelection(name: 'ignored')), same(view));
    }
    final custom = ChainExitPresentation.of(
      profile: _profile(),
      snapshot: const EngineSnapshot(
        phase: ConnectionPhase.connected,
        chainExit: ChainExitStatus(
          stage: 'connected',
          currentProfile: imported,
        ),
      ),
    );
    expect(custom.source, imported.source);
    expect(custom.selection?.name, imported.name);
    expect(custom.selection?.id, imported.id);
    expect(custom.statusLabel(strings), 'Connected');
  });

  test('an enabled chain makes no claim when the session omits its stage', () {
    for (final phase in [
      ConnectionPhase.connected,
      ConnectionPhase.degraded,
      ConnectionPhase.error,
    ]) {
      final view = ChainExitPresentation.of(
        profile: _profile(enabled: true, profileId: imported.id),
        snapshot: EngineSnapshot(phase: phase),
      );
      expect(view.statusLabel(strings), isNull, reason: '$phase');
      expect(view.live, isFalse);
    }
  });
}
