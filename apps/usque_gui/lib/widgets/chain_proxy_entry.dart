import 'package:flutter/material.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../core/chain_strings.dart';
import '../models/app_models.dart';
import '../state/app_controller.dart';
import 'chain_exit_summary.dart';
import 'common.dart';

/// Proxy-page section for the chain proxy, in the same open grammar as the
/// listener sections below it. Every source reads through one summary, so a
/// VPN Gate node and a saved configuration share wording and placement.
class ChainProxyEntry extends StatelessWidget {
  const ChainProxyEntry({
    required this.controller,
    required this.onOpen,
    super.key,
  });
  final AppController controller;
  final VoidCallback onOpen;

  /// Icon (20) plus the heading gap (12): the heading's text column.
  static const double textIndent = 32;

  @override
  Widget build(BuildContext context) => ChainExitSummaryBuilder(
    controller: controller,
    section: AppSection.proxy,
    builder: (context, view) {
      final strings = controller.strings;
      final theme = Theme.of(context);
      final label = view.statusLabel(strings);
      final status = label == null
          ? null
          : Semantics(
              liveRegion: true,
              child: InlineStatus(label: label, tone: view.tone),
            );
      // Same breakpoint as the listener sections, whose status also leaves
      // the heading row below it.
      final compact =
          MediaQuery.sizeOf(context).width < 760 ||
          MediaQuery.textScalerOf(context).scale(14) > 21;
      final chosen = view.live || view.selection != null;
      final hasChoice = chosen || view.enabled;
      return ContentSection(
        key: const ValueKey('proxy-chain-proxy-section'),
        icon: LucideIcons.link,
        title: strings.chain('title'),
        // Guidance stays until an exit is chosen, even for an enabled chain.
        subtitle: chosen ? null : strings.chain('subtitle'),
        trailing: compact ? null : status,
        gap: 4,
        child: Padding(
          padding: const EdgeInsetsDirectional.only(start: textIndent),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (hasChoice)
                ChainSelectionText(
                  view,
                  key: const ValueKey('proxy-chain-selection'),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              if (compact && status != null) ...[
                const SizedBox(height: 10),
                status,
              ],
              const SizedBox(height: 4),
              TextButton.icon(
                key: const ValueKey('proxy-chain-proxy-entry'),
                onPressed: onOpen,
                style: TextButton.styleFrom(
                  padding: EdgeInsets.zero,
                  alignment: AlignmentDirectional.centerStart,
                ),
                iconAlignment: IconAlignment.end,
                icon: const Icon(LucideIcons.chevronRight, size: 16),
                label: Text(strings.chain('manage')),
              ),
            ],
          ),
        ),
      );
    },
  );
}
