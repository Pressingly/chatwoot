import { createRouter, createWebHistory } from 'vue-router';

import routes from './routes';
import AnalyticsHelper from 'dashboard/helper/AnalyticsHelper';
import { validateRouteAccess } from '../helpers/RouteHelper';
import { frontendURL } from 'dashboard/helper/URLHelper';
import { isSSOBlockedRoute } from '../helpers/ssoRouteGuard';

export const router = createRouter({ history: createWebHistory(), routes });

const sensitiveRouteNames = ['auth_password_edit'];

export const initalizeRouter = () => {
  router.beforeEach((to, _, next) => {
    if (!sensitiveRouteNames.includes(to.name)) {
      AnalyticsHelper.page(to.name || '', {
        path: to.path,
        name: to.name,
      });
    }

    if (isSSOBlockedRoute(to)) {
      return next(frontendURL('login'));
    }

    return validateRouteAccess(to, next, window.chatwootConfig);
  });
};

export default router;
