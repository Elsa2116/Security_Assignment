import http from 'k6/http';
import { check, sleep } from 'k6';

// Keep the local smoke test intentionally small so it validates availability without stressing the development machine.
export const options = {
  vus: 5,
  duration: '30s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1000'],
  },
};

// Request the unauthenticated health endpoint because it is safe for repeatable load-test traffic.
export default function () {
  const response = http.get('http://host.docker.internal:3000/health');

  check(response, {
    'health endpoint returns 200': (result) => result.status === 200,
  });

  sleep(1);
}
