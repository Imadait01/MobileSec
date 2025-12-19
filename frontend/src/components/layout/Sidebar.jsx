import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useSettings } from '../../context/SettingsContext';

const Sidebar = () => {
    const location = useLocation();
    const { t } = useSettings();

    const menuItems = [
        { path: '/', key: 'dashboard', icon: '📊' },
        { path: '/reports', key: 'reports', icon: '📄' },
        { path: '/upload', key: 'new_scan', icon: '➕' },
        { path: '/scans', key: 'scan_history', icon: '🕒' },
        { path: '/settings', key: 'settings', icon: '⚙️' },
    ];

    return (
        <aside className="fixed left-0 top-0 h-screen w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 transition-colors duration-200">
            <div className="flex items-center justify-center h-16 border-b border-slate-200 dark:border-slate-800">
                <h1 className="text-xl font-bold text-slate-800 dark:text-white tracking-wider">
                    <span className="text-green-500">Mobile</span>Sec
                </h1>
            </div>

            <nav className="mt-6 px-4">
                <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-4">Main Menu</p>
                <ul className="space-y-2">
                    {menuItems.map((item) => (
                        <li key={item.path}>
                            <Link
                                to={item.path}
                                className={`flex items-center px-4 py-3 rounded-lg transition-colors duration-200 ${(item.path === '/' ? location.pathname === '/' : location.pathname.startsWith(item.path))
                                    ? 'bg-blue-50 text-blue-600 dark:bg-green-500/10 dark:text-green-500'
                                    : 'hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white'
                                    }`}
                            >
                                <span className="mr-3">{item.icon}</span>
                                {t(item.key)}
                            </Link>
                        </li>
                    ))}
                </ul>
            </nav>

            <div className="absolute bottom-0 w-full p-4 border-t border-slate-200 dark:border-slate-800">
                <div className="flex items-center">
                    <div className="w-8 h-8 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center text-xs text-slate-600 dark:text-white">
                        AU
                    </div>
                    <div className="ml-3">
                        <p className="text-sm font-medium text-slate-700 dark:text-white">Admin User</p>
                        <p className="text-xs text-slate-500">SecOps Team</p>
                    </div>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
