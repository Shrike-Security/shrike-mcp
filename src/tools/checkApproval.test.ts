/**
 * Unit tests for check_approval tool
 * Tests poll mode (all 5 statuses), decide mode, and error handling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkApproval } from './checkApproval.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock config
vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 5000,
    debug: false,
  },
  getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-key' }),
}));

// Suppress console.error in tests
vi.spyOn(console, 'error').mockImplementation(() => {});

describe('checkApproval', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // POLL MODE — status responses
  // =========================================================================

  describe('poll mode', () => {
    it('should return require_approval for pending status', async () => {
      const futureDate = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-123',
          status: 'pending',
          approval_level: 'edge',
          action_summary: 'SQL query requires approval',
          policy_name: 'Production DELETE',
          expires_at: futureDate,
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-123' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('require_approval');
      if (result.action === 'require_approval') {
        expect(result.approval_id).toBe('approval-123');
        expect(result.approval_context.policy_name).toBe('Production DELETE');
        expect(result.approval_context.approval_level).toBe('edge');
        expect(result.approval_context.expires_in_seconds).toBeGreaterThan(0);
        expect(result.agent_instruction).toContain('PENDING');
        expect(result.agent_instruction).toContain('Do NOT proceed');
        expect(result.agent_instruction).toContain('Do NOT poll in a loop');
      }

      // Verify correct URL called
      expect(mockFetch).toHaveBeenCalledWith(
        'https://mock-backend.test/api/v1/approvals/approval-123/status',
        expect.objectContaining({ method: 'GET' }),
      );
    });

    it('should return allow for approved status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-456',
          status: 'approved',
          approval_level: 'edge',
          action_summary: 'SQL query approved',
          policy_name: 'Production DELETE',
          expires_at: new Date().toISOString(),
          edge_decided_by: 'admin@company.com',
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-456' });

      expect(result.blocked).toBe(false);
      expect(result.action).toBe('allow');
      if (result.action === 'allow') {
        expect(result.agent_instruction).toContain('APPROVED');
        expect(result.agent_instruction).toContain('proceed');
        expect(result.audit.policy_name).toBe('Production DELETE');
      }
    });

    it('should return block for rejected status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-789',
          status: 'rejected',
          approval_level: 'edge',
          action_summary: 'SQL query rejected',
          policy_name: 'Production DELETE',
          expires_at: new Date().toISOString(),
          edge_justification: 'Too risky for production',
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-789' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.agent_instruction).toContain('REJECTED');
        expect(result.agent_instruction).toContain('Do NOT proceed');
        expect(result.guidance).toContain('Too risky for production');
        expect(result.user_message).toContain('Too risky for production');
      }
    });

    it('should return block for rejected status without justification', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-790',
          status: 'rejected',
          approval_level: 'edge',
          action_summary: 'SQL query rejected',
          policy_name: 'Production DELETE',
          expires_at: new Date().toISOString(),
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-790' });

      expect(result.blocked).toBe(true);
      if (result.action === 'block') {
        expect(result.user_message).toContain('Contact your security team');
      }
    });

    it('should return block for expired status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-exp',
          status: 'expired',
          approval_level: 'edge',
          action_summary: 'SQL query expired',
          policy_name: 'Production DELETE',
          expires_at: new Date(Date.now() - 60000).toISOString(),
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-exp' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.agent_instruction).toContain('EXPIRED');
        expect(result.user_message).toContain('expired');
        expect(result.severity).toBe('low');
      }
    });

    it('should return block for cancelled status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-can',
          status: 'cancelled',
          approval_level: 'edge',
          action_summary: 'SQL query cancelled',
          policy_name: 'Production DELETE',
          expires_at: new Date().toISOString(),
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-can' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.agent_instruction).toContain('CANCELLED');
        expect(result.user_message).toContain('cancelled');
      }
    });
  });

  // =========================================================================
  // DECIDE MODE
  // =========================================================================

  describe('decide mode', () => {
    it('should submit approved decision', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });

      const result = await checkApproval({
        approval_id: 'approval-123',
        decision: 'approved',
        justification: 'Verified with team',
      });

      expect(result.blocked).toBe(false);
      expect(result.action).toBe('allow');
      if (result.action === 'allow') {
        expect(result.agent_instruction).toContain('APPROVED');
        expect(result.agent_instruction).toContain('proceed');
      }

      // Verify POST with correct body
      expect(mockFetch).toHaveBeenCalledWith(
        'https://mock-backend.test/api/v1/approvals/approval-123/decide',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"decision":"approved"'),
        }),
      );

      // Verify body contains justification and decided_via
      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.justification).toBe('Verified with team');
      expect(callBody.decided_via).toBe('mcp');
    });

    it('should submit rejected decision', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });

      const result = await checkApproval({
        approval_id: 'approval-456',
        decision: 'rejected',
        justification: 'Too risky',
      });

      expect(result.blocked).toBe(false);
      expect(result.action).toBe('allow');
      if (result.action === 'allow') {
        expect(result.agent_instruction).toContain('REJECTED');
        expect(result.agent_instruction).toContain('Do NOT proceed');
      }
    });

    it('should handle decide API failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 409,
        text: async () => 'approval already decided',
      });

      const result = await checkApproval({
        approval_id: 'approval-789',
        decision: 'approved',
      });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.threat_type).toBe('scan_error');
        expect(result.guidance).toContain('409');
      }
    });
  });

  // =========================================================================
  // ERROR HANDLING
  // =========================================================================

  describe('error handling', () => {
    it('should handle poll API failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: async () => 'Approval not found',
      });

      const result = await checkApproval({ approval_id: 'nonexistent' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.threat_type).toBe('scan_error');
        expect(result.agent_instruction).toContain('Do NOT proceed');
      }
    });

    it('should handle network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const result = await checkApproval({ approval_id: 'approval-123' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.threat_type).toBe('scan_error');
      }
    });

    it('should handle timeout (AbortError)', async () => {
      const abortError = new DOMException('The operation was aborted', 'AbortError');
      mockFetch.mockRejectedValueOnce(abortError);

      const result = await checkApproval({ approval_id: 'approval-123' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.guidance).toContain('timed out');
      }
    });

    it('should URL-encode approval_id', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'id/with/slashes',
          status: 'pending',
          approval_level: 'edge',
          action_summary: 'test',
          policy_name: 'test',
          expires_at: new Date(Date.now() + 600000).toISOString(),
        }),
      });

      await checkApproval({ approval_id: 'id/with/slashes' });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('id%2Fwith%2Fslashes'),
        expect.anything(),
      );
    });
  });

  // =========================================================================
  // RESPONSE STRUCTURE
  // =========================================================================

  describe('response structure', () => {
    it('should always include request_id and audit block', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-struct',
          status: 'pending',
          approval_level: 'edge',
          action_summary: 'test',
          policy_name: 'TestPolicy',
          expires_at: new Date(Date.now() + 600000).toISOString(),
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-struct' });

      expect(result.request_id).toBeDefined();
      expect(result.request_id).toMatch(/^req_/);
      expect(result.audit).toBeDefined();
      expect(result.audit.scan_id).toBeDefined();
      expect(result.audit.timestamp).toBeDefined();
    });

    it('should compute expires_in_seconds correctly for pending', async () => {
      const futureDate = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min from now
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-time',
          status: 'pending',
          approval_level: 'edge',
          action_summary: 'test',
          policy_name: 'test',
          expires_at: futureDate,
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-time' });

      if (result.action === 'require_approval') {
        // Should be approximately 600 seconds (10 min), allow ±5 sec margin
        expect(result.approval_context.expires_in_seconds).toBeGreaterThan(595);
        expect(result.approval_context.expires_in_seconds).toBeLessThan(605);
      }
    });

    it('should clamp expires_in_seconds to 0 for past dates', async () => {
      const pastDate = new Date(Date.now() - 60000).toISOString(); // 1 min ago
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-past',
          status: 'pending',
          approval_level: 'edge',
          action_summary: 'test',
          policy_name: 'test',
          expires_at: pastDate,
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-past' });

      if (result.action === 'require_approval') {
        expect(result.approval_context.expires_in_seconds).toBe(0);
      }
    });
  });
});
