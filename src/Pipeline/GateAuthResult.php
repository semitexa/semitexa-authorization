<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Pipeline;

use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Request;
use Semitexa\Core\Support\CoroutineLocal;

/**
 * The authentication the pre-hydration gate already did, handed to the
 * AuthorizationListener of the same request.
 *
 * Both ran the auth handlers: every protected or service request was
 * authenticated twice — two Argon2id checks for a machine token, and its use
 * recorded twice. Single use, and only for the request object it was taken
 * from, so nothing carries over to another request in the coroutine.
 */
final class GateAuthResult
{
    private const KEY = 'semitexa.authorization.gate_auth_result';

    public static function remember(Request $request, AuthResult $result): void
    {
        // A weak reference, not spl_object_id(): a freed Request's id goes to
        // the next object PHP makes, and on a long-lived stream that can be
        // the next tick's Request.
        CoroutineLocal::set(self::KEY, [\WeakReference::create($request), $result]);
    }

    public static function takeFor(Request $request): ?AuthResult
    {
        $remembered = CoroutineLocal::get(self::KEY);
        self::forget();

        return is_array($remembered)
            && $remembered[0] instanceof \WeakReference
            && $remembered[0]->get() === $request
            && $remembered[1] instanceof AuthResult
            ? $remembered[1]
            : null;
    }

    public static function forget(): void
    {
        CoroutineLocal::remove(self::KEY);
    }
}
