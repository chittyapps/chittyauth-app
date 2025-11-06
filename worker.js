/**
 * ChittyAuth - Authentication & Token Provisioning Service
 * Production Endpoint: https://auth.chitty.cc
 *
 * Centralized authentication service for the ChittyOS ecosystem.
 * Provisions, validates, and manages API tokens for all services.
 */

import { ChittyAuthAPI } from './src/api-router.js';

export default {
  async fetch(request, env, ctx) {
    const api = new ChittyAuthAPI(env);

    try {
      return await api.route(request);
    } catch (error) {
      console.error('ChittyAuth worker error:', error);

      return new Response(JSON.stringify({
        success: false,
        error: 'Internal server error',
        message: error.message,
        timestamp: new Date().toISOString()
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  }
};
