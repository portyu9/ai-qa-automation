import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 2,
  duration: '10s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
  },
};

const baseUrl = __ENV.BASE_URL || 'http://127.0.0.1:8000';

export default function () {
  const response = http.get(`${baseUrl}/health`);
  check(response, { 'health returns 200': (r) => r.status === 200 });
}
