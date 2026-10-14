import 'package:flutter/foundation.dart';

import '../models/app_models.dart';
import '../widgets/common.dart' show StatusTone;
import 'app_strings.dart';
import 'chain_home_status.dart';
import 'chain_strings.dart';

/// What the chain proxy uses: a VPN Gate node or a configuration name.
/// [id] identifies a configuration, and keeps a saved VPN Gate choice
/// readable before its node resolves.
@immutable
class ChainSelection {
  const ChainSelection({this.server, this.name, this.id});
  final VpnGateServer? server;
  final String? name;
  final String? id;

  @override
  bool operator ==(Object other) =>
      other is ChainSelection &&
      server == other.server &&
      name == other.name &&
      id == other.id;

  @override
  int get hashCode => Object.hash(server, name, id);
}

/// One reading of the chain proxy shared by Home and the Proxy page.
///
/// The status comes from [ChainHomeStatus], so the text beside the switch
/// always agrees with the connection ring. An enabled chain whose session
/// reports no chain stage makes no claim, as on Home.
@immutable
class ChainExitPresentation {
  const ChainExitPresentation._({
    required this.enabled,
    required this.source,
    required this.selection,
    required this.live,
    required this.savedKey,
    required this.statusKey,
    required this.chainCatalog,
    required this.tone,
  });

  factory ChainExitPresentation.of({
    required UsqueProfile profile,
    required EngineSnapshot snapshot,
    ChainSelection? saved,
  }) {
    final chain = snapshot.chainExit;
    final gate = snapshot.vpnGate;
    final home = ChainHomeStatus.of(
      phase: snapshot.phase,
      chainEnabled: profile.chainEnabled,
      chainStage: chain.stage,
      gateStage: gate.stage,
      hasCurrentProfile: chain.currentProfile != null,
      hasGateServer: gate.server != null,
    );
    final session =
        home.showChainRow && snapshot.phase != ConnectionPhase.disconnected;
    final current = session ? chain.currentProfile : null;
    final server = session && current == null ? gate.server : null;
    final source =
        current?.source ??
        (server != null ? ChainSource.vpnGate : profile.chainSource);
    final live = current != null || server != null;
    final savedKey = live ? null : savedSelectionKey(profile);
    final selection = current != null
        ? ChainSelection(name: current.name, id: current.id)
        : server != null
        ? ChainSelection(server: server)
        : savedKey == null
        ? null
        : saved ??
              (source == ChainSource.vpnGate
                  ? ChainSelection(id: profile.vpnGate.serverId)
                  : null);
    final (String? key, bool catalog, StatusTone tone) = home.showChainRow
        ? (home.labelKey, home.chainCatalog, home.tone)
        : profile.chainEnabled
        ? (null, true, StatusTone.neutral)
        : ('disabled', true, StatusTone.neutral);
    return ChainExitPresentation._(
      enabled: profile.chainEnabled,
      source: source,
      selection: selection,
      live: live,
      savedKey: savedKey,
      statusKey: key,
      chainCatalog: catalog,
      tone: tone,
    );
  }

  /// Identifies the stored choice for a one-time lookup, or null when the
  /// chain proxy has nothing saved for its configured source.
  static String? savedSelectionKey(UsqueProfile profile) {
    final source = profile.chainSource;
    if (source == ChainSource.vpnGate) {
      final gate = profile.vpnGate;
      return gate.hasSelection
          ? '${source.wire}:${gate.serverId}:${gate.configSha256}'
          : null;
    }
    final exit = profile.chainExit;
    final id = exit?.source == source ? exit?.profileId : null;
    return id == null ? null : '${source.wire}:$id:${exit?.revision ?? ''}';
  }

  final bool enabled;
  final ChainSource source;
  final ChainSelection? selection;

  /// The selection comes from the running session rather than settings.
  final bool live;
  final String? savedKey;

  /// Null when the session cannot say what the chain is doing.
  final String? statusKey;
  final bool chainCatalog;
  final StatusTone tone;

  /// Fills in the resolved saved choice; a live selection always wins.
  ChainExitPresentation withSaved(ChainSelection saved) =>
      live || savedKey == null
      ? this
      : ChainExitPresentation._(
          enabled: enabled,
          source: source,
          selection: saved,
          live: live,
          savedKey: savedKey,
          statusKey: statusKey,
          chainCatalog: chainCatalog,
          tone: tone,
        );

  String? statusLabel(AppStrings strings) => statusKey == null
      ? null
      : chainCatalog
      ? strings.chain(statusKey!)
      : strings.get(statusKey!);

  @override
  bool operator ==(Object other) =>
      other is ChainExitPresentation &&
      enabled == other.enabled &&
      source == other.source &&
      selection == other.selection &&
      live == other.live &&
      savedKey == other.savedKey &&
      statusKey == other.statusKey &&
      chainCatalog == other.chainCatalog &&
      tone == other.tone;

  @override
  int get hashCode => Object.hash(
    enabled,
    source,
    selection,
    live,
    savedKey,
    statusKey,
    chainCatalog,
    tone,
  );
}
