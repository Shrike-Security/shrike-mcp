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
      // SHRIKE-302: Backend returns expires_in_seconds (precomputed), not expires_at
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-123',
          status: 'pending',
          expires_in_seconds: 900,
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-123' });

      expect(result.blocked).toBe(true);
      expect(result.action).toBe('require_approval');
      if (result.action === 'require_approval') {
        expect(result.approval_id).toBe('approval-123');
        expect(result.approval_context.expires_in_seconds).toBe(900);
        expect(result.agent_instruction).toContain('PENDING');
        expect(result.agent_instruction).toContain('15 minutes');
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
          decided_by: 'admin@company.com',
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-456' });

      expect(result.blocked).toBe(false);
      expect(result.action).toBe('allow');
      if (result.action === 'allow') {
        expect(result.agent_instruction).toContain('APPROVED');
        expect(result.agent_instruction).toContain('proceed');
      }
    });

    it('should return block for rejected status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-789',
          status: 'rejected',
          justification: 'Too risky for production',
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

    it('should submit rejected decision with blocked:true', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });

      const result = await checkApproval({
        approval_id: 'approval-456',
        decision: 'rejected',
        justification: 'Too risky',
      });

      // SHRIKE-301: Rejection must return blocked:true so agents stop
      expect(result.blocked).toBe(true);
      expect(result.action).toBe('block');
      if (result.action === 'block') {
        expect(result.agent_instruction).toContain('REJECTED');
        expect(result.agent_instruction).toContain('Do NOT proceed');
        expect(result.user_message).toContain('Too risky');
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
          expires_in_seconds: 600,
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
          expires_in_seconds: 600,
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
      // SHRIKE-302: Backend returns precomputed expires_in_seconds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-time',
          status: 'pending',
          expires_in_seconds: 600,
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-time' });

      if (result.action === 'require_approval') {
        expect(result.approval_context.expires_in_seconds).toBe(600);
      }
    });

    it('should use 0 when expires_in_seconds is not provided', async () => {
      // SHRIKE-302: When backend omits expires_in_seconds, default to 0
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'approval-past',
          status: 'pending',
        }),
      });

      const result = await checkApproval({ approval_id: 'approval-past' });

      if (result.action === 'require_approval') {
        expect(result.approval_context.expires_in_seconds).toBe(0);
      }
    });
  });
});
