/// Typed administration API client (SDK-003, SDK-007): RFC 9457 problems,
/// cursor pagination, idempotency keys, If-Match, deadlines and
/// cancellation, one-time secrets wrapped in [Secret], deprecation
/// reporting.
library;

export 'src/admin.dart'
    show
        AdminClient,
        AdminErrorCode,
        AdminRequestException,
        AdminResponse,
        ApiObject,
        DeprecationNotice,
        EffectivePermissions,
        InvitationSummary,
        Membership,
        OAuthClientSummary,
        Organization,
        Page,
        ProblemException,
        Ref,
        RequestOptions,
        Role,
        Secret,
        SessionSummary,
        SupportGrant,
        TokenSource,
        User,
        UserStateAction,
        newIdempotencyKey,
        sdkVersion,
        secretMembers;
export 'src/cancel.dart' show CancelToken;
