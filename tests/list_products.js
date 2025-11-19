import http from "k6/http";
import { sleep, check } from "k6";

export const options = {
  vus: 50,
  duration: "30s",
};

const AUTH_TOKEN = __ENV.JWT_SECRET;

export default function () {
  const params = {
    headers: {
      Authorization: `Bearer ${AUTH_TOKEN}`,
      "Content-Type": "application/json",
    },
  };
  const url = "http://localhost:8080/api/catalog/v1/products/list";
  const res = http.get(url, params);

  check(res, { "status 200": (r) => r.status === 200 });
  sleep(0.2);
}
