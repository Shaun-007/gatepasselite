// Gate pass routes: apply, list, approve, reject and the QR code image.
const { Router } = require('express');
const crypto = require('node:crypto');
const QRCode = require('qrcode');
const { requireRole } = require('../session');

const PENDING = 'PENDING';
const APPROVED = 'APPROVED';
const REJECTED = 'REJECTED';

module.exports = function gatePassRoutes({ db }) {
  const router = Router();

  // Add the student's name/room to a pass, so every page can show it directly.
  async function passWithStudent(pass) {
    if (!pass) return null;
    const student = await db.get('SELECT name, loginId, roomNumber FROM users WHERE id = ?', [pass.studentId]);
    return {
      ...pass,
      studentName: student ? student.name : 'Unknown',
      studentLoginId: student ? student.loginId : '-',
      roomNumber: student ? student.roomNumber : '-',
    };
  }

  // POST /api/gatepasses  { reason, fromDateTime, toDateTime }
  // A student asks for a new pass.
  router.post('/', requireRole('STUDENT'), async (req, res) => {
    try {
      const { reason, fromDateTime, toDateTime } = req.body || {};
      if (!reason || !fromDateTime || !toDateTime) {
        return res.status(400).json({ error: 'Please fill in reason, leaving time and return time.' });
      }
      if (new Date(toDateTime) <= new Date(fromDateTime)) {
        return res.status(400).json({ error: 'Return time must be after leaving time.' });
      }

      const result = await db.run(
        "INSERT INTO gate_passes (studentId, reason, fromDateTime, toDateTime, status) VALUES (?, ?, ?, ?, ?)",
        [req.user.id, reason, fromDateTime, toDateTime, PENDING]
      );

      const pass = await db.get('SELECT * FROM gate_passes WHERE id = ?', [result.lastInsertRowid]);
      res.status(201).json({ pass: await passWithStudent(pass) });
    } catch (err) {
      console.error('Create gatepass error:', err);
      res.status(500).json({ error: 'Failed to create gate pass.' });
    }
  });

  // GET /api/gatepasses
  // Students see their own passes; wardens see everyone's.
  router.get('/', requireRole('STUDENT', 'WARDEN'), async (req, res) => {
    try {
      const rows =
        req.user.role === 'WARDEN'
          ? await db.all('SELECT * FROM gate_passes ORDER BY id DESC')
          : await db.all('SELECT * FROM gate_passes WHERE studentId = ? ORDER BY id DESC', [req.user.id]);
      res.json({ passes: await Promise.all(rows.map(passWithStudent)) });
    } catch (err) {
      console.error('List gatepasses error:', err);
      res.status(500).json({ error: 'Failed to fetch gate passes.' });
    }
  });

  // POST /api/gatepasses/:id/approve   (warden only)
  router.post('/:id/approve', requireRole('WARDEN'), async (req, res) => {
    try {
      const pass = await db.get('SELECT * FROM gate_passes WHERE id = ?', [req.params.id]);
      if (!pass) return res.status(404).json({ error: 'Gate pass not found.' });
      if (pass.status !== PENDING) {
        return res.status(400).json({ error: 'Only pending passes can be approved.' });
      }

      // The QR code stores only this random token - never personal data.
      const qrToken = 'GP-' + crypto.randomBytes(4).toString('hex').toUpperCase();
      await db.run("UPDATE gate_passes SET status = ?, qrToken = ? WHERE id = ?", [APPROVED, qrToken, pass.id]);

      const updated = await db.get('SELECT * FROM gate_passes WHERE id = ?', [pass.id]);
      res.json({ pass: await passWithStudent(updated) });
    } catch (err) {
      console.error('Approve pass error:', err);
      res.status(500).json({ error: 'Failed to approve gate pass.' });
    }
  });

  // POST /api/gatepasses/:id/reject   (warden only)
  router.post('/:id/reject', requireRole('WARDEN'), async (req, res) => {
    try {
      const pass = await db.get('SELECT * FROM gate_passes WHERE id = ?', [req.params.id]);
      if (!pass) return res.status(404).json({ error: 'Gate pass not found.' });
      if (pass.status !== PENDING) {
        return res.status(400).json({ error: 'Only pending passes can be rejected.' });
      }

      await db.run("UPDATE gate_passes SET status = ? WHERE id = ?", [REJECTED, pass.id]);
      const updated = await db.get('SELECT * FROM gate_passes WHERE id = ?', [pass.id]);
      res.json({ pass: await passWithStudent(updated) });
    } catch (err) {
      console.error('Reject pass error:', err);
      res.status(500).json({ error: 'Failed to reject gate pass.' });
    }
  });

  // GET /api/gatepasses/:id/qr   (student only, their own approved pass)
  // Returns the QR code as a PNG image to show at the gate.
  router.get('/:id/qr', requireRole('STUDENT'), async (req, res) => {
    try {
      const pass = await db.get('SELECT * FROM gate_passes WHERE id = ?', [req.params.id]);
      if (!pass || pass.studentId !== req.user.id) {
        return res.status(404).json({ error: 'Gate pass not found.' });
      }
      if (pass.status !== APPROVED || !pass.qrToken) {
        return res.status(400).json({ error: 'This pass is not approved yet, so it has no QR code.' });
      }

      QRCode.toBuffer(pass.qrToken, { width: 320, margin: 2 }, (error, buffer) => {
        if (error) return res.status(500).json({ error: 'Could not create the QR code.' });
        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Cache-Control', 'public, max-age=3600');
        res.send(buffer);
      });
    } catch (err) {
      console.error('QR code error:', err);
      res.status(500).json({ error: 'Could not load QR code.' });
    }
  });

  return router;
};