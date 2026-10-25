import { FileText, LayoutGrid, Radar, ShieldAlert, SlidersHorizontal, Workflow } from 'lucide-react';

const BASE_ITEMS = [
  { id: 'dashboard', label: 'Overview', icon: LayoutGrid, hint: 'Command center' },
  { id: 'logs', label: 'Log explorer', icon: FileText, hint: 'MongoDB' },
  { id: 'alerts', label: 'Threats & alerts', icon: ShieldAlert, hint: 'Triage' },
  { id: 'incidents', label: 'Investigations', icon: Workflow, hint: 'Response' },
  { id: 'detection', label: 'Detection rules', icon: Radar, hint: 'Engine' },
];

const ADMIN_ITEM = { id: 'admin', label: 'Administration', icon: SlidersHorizontal, hint: 'Admin only' };

/** Sections the given user may open, in sidebar order. */
export function getNavItems(user) {
  return user?.role_name === 'ADMIN' ? [...BASE_ITEMS, ADMIN_ITEM] : BASE_ITEMS;
}
