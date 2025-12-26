import request from 'supertest';
import app from '../../server'; // assumes an express app export

describe('POST /api/reports', () => {
  it('should return JSON when format=json', async () => {
    const payload = {
      format: 'json',
      template: 'security_report',
      metadata: { appName: 'TestApp' },
      results: {
        secretHunter: [{ title: 'Secret', description: 'Found secret', severity: 'high' }]
      }
    };

    const res = await request(app).post('/api/reports').send(payload).expect(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body).toHaveProperty('vulnerabilities');
  });
});
