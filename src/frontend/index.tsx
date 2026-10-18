import { KeyRound } from "lucide-react";
import type { TabProps, TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { createKeePassApi } from "./api";
import { KeePassTab } from "./KeePassTab";

const TAB_ID = "keepass";

export function activate(app: TermixApp): void {
  const api = createKeePassApi(app.api);

  app.registerRailItem({
    id: TAB_ID,
    icon: KeyRound,
    titleKey: "tab.title",
    kind: "tab",
    permission: "use",
  });
  app.registerTab(
    TAB_ID,
    (props: TabProps) => <KeePassTab {...props} api={api} />,
    {
      icon: KeyRound,
      titleKey: "tab.title",
      singleton: true,
      hostless: true,
    },
  );
}
