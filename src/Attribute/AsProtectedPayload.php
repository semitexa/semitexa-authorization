<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Attribute;

use Attribute;
use Semitexa\Core\Attribute\AbstractPayloadRoute;
use Semitexa\Core\Attribute\Capability;
use Semitexa\Core\Auth\PayloadAccessType;

/**
 * Marks a payload as user-facing protected — requires user/session/admin/
 * customer authentication. May be combined with #[RequiresCapability] and
 * #[RequiresPermission] for fine-grained authorization.
 *
 * For machine-to-machine endpoints (webhook receivers, partner APIs, signed
 * integrations) declare #[AsServicePayload] instead. Service is a separate
 * access class, not a flavor of protected.
 *
 * @api
 */
#[Capability(
    id: 'authorization.protected-page',
    summary: 'A page only a signed-in visitor sees: #[AsProtectedPayload] refuses a guest before the handler runs, and with authentication on (semitexa/auth, AUTH_ENABLED not false) before the payload is hydrated.',
    useWhen: 'A page shows, or changes, things that belong to whoever is signed in: a profile, an account, settings, a dashboard.',
    avoidWhen: 'Anyone may see the page; then #[AsPublicPayload], with a reason when it reads who is signed in or sits on a private-sounding path.',
    replaces: [
        'a public page whose handler checks isGuest() or getUser() and renders a guest card instead',
        'a redirect to the login page written in the handler',
    ],
    seeAlso: 'semitexa/platform-user',
    usage: <<<'USAGE'
        // A guest never reaches the handler: an HTML request gets the error.401 route (the
        // module's sign-in page) with status 401, JSON gets the 401 body.
        #[AsProtectedPayload(path: '/account/profile', methods: ['GET'], responseWith: ProfileResource::class)]
        final class ProfilePayload
        {
        }

        // A public page that reads who is signed in says why, and the lints accept it:
        #[AsPublicPayload(path: '/sign-in', methods: ['GET'], responseWith: SignInResource::class,
            reason: 'sign-in page: greets a returning visitor')]
        final class SignInPayload
        {
        }
        USAGE,
)]
#[Attribute(Attribute::TARGET_CLASS)]
final class AsProtectedPayload extends AbstractPayloadRoute
{
    public function getAccessType(): PayloadAccessType
    {
        return PayloadAccessType::Protected;
    }
}
