async function fetchPost(url, data, headers) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(data),
  });
  return await response.json();
}

async function fetchGet(url, headers) {
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
  return await response.json();
}
function timer() {
    let startTime = (new Date()).getTime();
    while ((new Date()).getTime() - startTime < 1000) {
        continue;
    }
}
async function main() {
  const url = 'https://jsonplaceholder.typicode.com/posts';
  const params = {body: 'bar',userId: 1};
  const headers = {};
  const data = await fetchPost(url, params, headers);
}
main();