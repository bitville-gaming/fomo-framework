<?php

namespace Fomo\Servers;

use App\Exceptions\Handler;
use FastRoute\Dispatcher;
use FastRoute\RouteCollector;
use Swoole\Server;
use Fomo\Request\Request;
use Fomo\Router\Router;

class Http
{
    protected Dispatcher $dispatcher;
    protected Request $request;
    protected Server $server;
    protected array $cache = [];
    protected array $config = [];
    protected array $MPCache = [];

    /**
     * Incomplete TCP segments per connection (see TCP packet boundary / stream reassembly).
     * Same $fd stays on the same worker unless dispatch_mode is 3.
     * @link https://wiki.swoole.com/en/#/server/events?id=onreceive
     * @link https://wiki.swoole.com/en/#/learn?id=tcp-packet-boundary-issue
     *
     * @var array<int, string>
     */
    protected array $tcpBuffers = [];

    public function createServer(): self
    {
        $this->server = new Server(
            config('server.host') ,
            config('server.port') ,
            !is_null(config('server.ssl.ssl_cert_file')) && !is_null(config('server.ssl.ssl_key_file')) ? config('server.mode') | SWOOLE_SSL : config('server.mode') ,
            config('server.sockType')
        );

        $this->server->set(array_merge(config('server.additional'), [
            'enable_coroutine' => false,
            'open_http_protocol' => true,
        ]));

        $this->server->on('workerStart', [$this, 'onWorkerStart']);
        $this->server->on('receive', [$this, 'onReceive']);
        $this->server->on('close', [$this, 'onClose']);

        return $this;
    }

    public function start(bool $daemonize = false): void
    {
        if ($daemonize === true){
            $this->server->set([
                'daemonize' => 1
            ]);
        }
        $this->server->start();
    }

    public function onWorkerStart(Server $server, int $workerId): void
    {
        if ($workerId == config('server.additional.worker_num') - 1){
            $this->saveWorkerIds();
        }

        $this->dispatcher = \FastRoute\simpleDispatcher(function (RouteCollector $r) {
            $router = new Router();
            $router->group([], function ($router) {
                require_once basePath("routes/api.php");
            });

            foreach ($router->getRoutes() as $method => $callbacks)
                foreach ($callbacks as $callback)
                    $r->addRoute($method, $callback[0] , $callback[1]);
        });

        $this->request = new Request($server , $this->dispatcher);
        $this->runServices($server);
    }

    public function onClose(Server $server, int $fd): void
    {
        unset($this->tcpBuffers[$fd]);
    }

    public function onReceive(Server $server, $fd, $from_id, $data): void
    {
        $maxPackage = (int) (config('server.additional.package_max_length') ?? 8 * 1024 * 1024);
        $this->tcpBuffers[$fd] = ($this->tcpBuffers[$fd] ?? '') . $data;

        if (\strlen($this->tcpBuffers[$fd]) > $maxPackage) {
            unset($this->tcpBuffers[$fd]);
            try {
                $server->send($fd, "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            } catch (\Throwable) {
            }
            $server->close($fd);

            return;
        }

        while (($full = $this->takeNextCompleteHttpMessage($fd)) !== null) {
            $this->dispatchHttpMessage($server, $fd, $full);
        }
    }

    /**
     * Reassemble one HTTP/1.x message from the per-fd buffer (headers + entity body).
     * Supports Content-Length and chunked transfer coding.
     */
    protected function takeNextCompleteHttpMessage(int $fd): ?string
    {
        if (!isset($this->tcpBuffers[$fd])) {
            return null;
        }

        $buf = &$this->tcpBuffers[$fd];
        $headerEnd = \strpos($buf, "\r\n\r\n");
        if ($headerEnd === false) {
            return null;
        }

        $headersRaw = \substr($buf, 0, $headerEnd);
        $bodyStart = $headerEnd + 4;
        $chunked = (bool) \preg_match('/^Transfer-Encoding\s*:\s*(?:[^,\r\n]+,\s*)*chunked\b/im', $headersRaw)
            || (bool) \preg_match('/\r\nTransfer-Encoding\s*:\s*(?:[^,\r\n]+,\s*)*chunked\b/im', $headersRaw);

        if ($chunked) {
            $end = $this->findChunkedHttpMessageEnd($buf, $bodyStart);
            if ($end === null) {
                return null;
            }
            $message = \substr($buf, 0, $end);
            $buf = \substr($buf, $end);

            return $message;
        }

        if (\preg_match('/\bContent-Length[\x09\x20]*:[\x09\x20]*(\d+)/i', $headersRaw, $m)) {
            $contentLength = (int) $m[1];
            $total = $bodyStart + $contentLength;
            if (\strlen($buf) < $total) {
                return null;
            }
            $message = \substr($buf, 0, $total);
            $buf = \substr($buf, $total);

            return $message;
        }

        $message = \substr($buf, 0, $bodyStart);
        $buf = \substr($buf, $bodyStart);

        return $message;
    }

    /**
     * @return int|null byte offset immediately after the full HTTP message (chunked) in $buf
     */
    protected function findChunkedHttpMessageEnd(string $buf, int $offset): ?int
    {
        $len = \strlen($buf);
        $pos = $offset;

        while (true) {
            $crlf = \strpos($buf, "\r\n", $pos);
            if ($crlf === false) {
                return null;
            }

            $line = \substr($buf, $pos, $crlf - $pos);
            $semi = \strpos($line, ';');
            $hexPart = $semi === false ? $line : \substr($line, 0, $semi);
            $hexPart = \ltrim(\strtolower($hexPart), " \t");
            if ($hexPart === '' || !\ctype_xdigit($hexPart)) {
                return null;
            }

            $chunkSize = \hexdec($hexPart);
            $chunkDataStart = $crlf + 2;

            if ($chunkSize > 0) {
                if ($len < $chunkDataStart + $chunkSize + 2) {
                    return null;
                }
                if (\substr($buf, $chunkDataStart + $chunkSize, 2) !== "\r\n") {
                    return null;
                }
                $pos = $chunkDataStart + $chunkSize + 2;

                continue;
            }

            $trailerEnd = \strpos($buf, "\r\n\r\n", $chunkDataStart);
            if ($trailerEnd === false) {
                return null;
            }

            return $trailerEnd + 4;
        }
    }

    protected function dispatchHttpMessage(Server $server, int $fd, string $data): void
    {
        try {
            $this->request->setBC($data, $fd);
            $firstLine = \strstr($data, "\r\n", true);

            if (isset($this->MPCache[$firstLine])) {
                $method = $this->MPCache[$firstLine][0];
                $path = $this->MPCache[$firstLine][1];
            } else {
                if (\count($this->MPCache) >= 256) {
                    unset($this->MPCache[key($this->MPCache)]);
                }

                $MP = \explode(' ', $firstLine, 3);
                $path = \strstr($MP[1], '?', true);
                $path = $path === false ? $MP[1] : $path;
                $method = $MP[0];
                $this->MPCache[$firstLine] = [$method, $path];
            }

            $cache = $this->cache[$method . $path] ?? null;

            if (!is_null($cache)) {
                if ($cache[2] !== null) {
                    foreach ($cache[2] as $middleware) {
                        $callback = $middleware->handle($this->request);
                        if ($callback !== true) {
                            $server->send($fd, $callback);
                            return;
                        }
                    }
                }

                $server->send($fd, $cache[0]->{$cache[1]}($this->request, ...$cache[3]));

                return;
            }

            $routeInfo = $this->dispatcher->dispatch($method, $path);
            if ($routeInfo[0] === 1) {
                if (count($this->cache) > 1024) {
                    $this->cache = [];
                }
                $this->cache[$method . $path] = [
                    $routeInfo[1][0],
                    $routeInfo[1][1],
                    $routeInfo[1]['middleware'] ?? null,
                    $routeInfo[2]
                ];

                if (isset($routeInfo[1]['middleware'])) {
                    foreach ($routeInfo[1]['middleware'] as $middleware) {
                        $callback = $middleware->handle($this->request);
                        if ($callback !== true) {
                            $server->send($fd, $callback);
                            return;
                        }
                    }
                }

                $server->send($fd, $routeInfo[1][0]->{$routeInfo[1][1]}($this->request, ...$routeInfo[2]));
            } elseif ($routeInfo[0] === 0) {
                $server->send($fd, (new Handler())->notFoundHttpException($this->request));
            } else {
                $server->send($fd, (new Handler())->notAllowedHttpException($this->request));
            }

        } catch (\Throwable|\Exception $e) {
            $server->send($fd, (new Handler())->internalServerException($e, $this->request));
        }
    }

    protected function saveWorkerIds(): void
    {
        $workerIds = [];
        for ($i = 0; $i < config('server.additional.worker_num'); $i++){
            $workerIds[$i] = $this->server->getWorkerPid($i);
        }

        setMasterProcessId($this->server->getMasterPid());
        setManagerProcessId($this->server->getManagerPid());
        setWorkerProcessIds($workerIds);
    }

    protected function runServices(Server $server): void
    {
        foreach (config('server.services') as $service){
            (new $service)->boot($server , $this->request);
        }
    }
}
