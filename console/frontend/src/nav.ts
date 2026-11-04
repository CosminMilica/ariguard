// Two-level navigation model: six top-level sections, each grouping one or more leaf pages.
// The leaf page (store.page) stays the single source of truth for routing; the sidebar picks a
// section and expands its leaf pages inline as nested sub-items. Keeps page components untouched
// while collapsing the flat 14-tab list into a legible structure.
import type { Page } from './api'

export interface NavLeaf { page: Page; label: string }
export interface NavSection { key: string; label: string; icon: string; pages: NavLeaf[] }

export const NAV: NavSection[] = [
  {
    key: 'overview', label: 'Overview',
    icon: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    pages: [{ page: 'overview', label: 'Overview' }],
  },
  {
    key: 'threats', label: 'Threats',
    icon: '<path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 10v4m0 3v.01"/>',
    pages: [{ page: 'triage', label: 'Live' }, { page: 'incidents', label: 'History' }],
  },
  {
    key: 'workloads', label: 'Workloads',
    icon: '<rect x="3" y="4" width="18" height="5" rx="1"/><rect x="3" y="11" width="18" height="5" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/>',
    pages: [{ page: 'workloads', label: 'Workloads' }],
  },
  {
    key: 'analysis', label: 'Analysis',
    icon: '<circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="18" r="2.5"/><circle cx="18" cy="6" r="2.5"/><path d="M7.3 7.3 16 16.5M15.5 6h-8M6 8.3 17 16"/>',
    pages: [
      { page: 'actors', label: 'Actors' },
      { page: 'campaigns', label: 'Blast radius' },
      { page: 'lateral', label: 'Network pivots' },
    ],
  },
  {
    key: 'activity', label: 'Activity',
    icon: '<path d="M4 18V9m5 9V5m5 13v-6m5 6V8"/>',
    pages: [{ page: 'timeline', label: 'Timeline' }, { page: 'events', label: 'Severity' }],
  },
  {
    key: 'system', label: 'System',
    icon: '<path d="M12 3 4 6v6c0 5 3.5 7.5 8 9 4.5-1.5 8-4 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>',
    pages: [
      { page: 'coverage', label: 'Coverage' },
      { page: 'rules', label: 'Rules' },
      { page: 'nodes', label: 'Nodes' },
      { page: 'performance', label: 'Performance' },
    ],
  },
]

// sectionOf returns the section that owns a page (defaults to the first).
export function sectionOf(page: Page): NavSection {
  return NAV.find(s => s.pages.some(p => p.page === page)) ?? NAV[0]
}
