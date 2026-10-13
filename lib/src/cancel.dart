import 'dart:async';

/// Lets a caller stop waiting for an operation, the Dart counterpart of the
/// `AbortSignal` options of the Node.js SDK.
///
/// Cancelling a token stops the requests and waits it was passed to. Shared
/// work that other callers depend on (a coalesced key-set fetch or a
/// single-flight refresh) keeps running; only this caller stops waiting.
final class CancelToken {
  /// A token that is cancelled when [cancel] is called.
  CancelToken();

  /// A token that cancels itself after [duration].
  factory CancelToken.timeout(Duration duration) {
    final token = CancelToken();
    token._timer = Timer(duration, token.cancel);
    return token;
  }

  /// A token that is cancelled as soon as any of [tokens] is.
  ///
  /// Cancel the returned token once it is no longer needed: that also
  /// detaches it from [tokens], so long-lived tokens do not accumulate
  /// listeners.
  factory CancelToken.any(Iterable<CancelToken> tokens) {
    final token = CancelToken();
    final removers = <void Function()>[];
    for (final t in tokens) {
      if (t.isCancelled) {
        token.cancel();
        break;
      }
      removers.add(onCancel(t, token.cancel));
    }
    void detach() {
      for (final r in removers) {
        r();
      }
    }

    if (token.isCancelled) {
      detach();
    } else {
      onCancel(token, detach);
    }
    return token;
  }

  final Completer<void> _done = Completer<void>();
  final Set<void Function()> _callbacks = <void Function()>{};
  Timer? _timer;
  bool _cancelled = false;

  /// Whether [cancel] has been called.
  bool get isCancelled => _cancelled;

  /// Completes when the token is cancelled.
  Future<void> get whenCancelled => _done.future;

  /// Cancels the token. Calling it again has no effect.
  void cancel() {
    if (_cancelled) return;
    _cancelled = true;
    _timer?.cancel();
    final callbacks = List.of(_callbacks);
    _callbacks.clear();
    for (final cb in callbacks) {
      try {
        cb();
      } catch (_) {
        // A failing listener must not prevent the others from running.
      }
    }
    _done.complete();
  }
}

/// Registers [callback] for [token] (immediately when it is already
/// cancelled) and returns a function that unregisters it.
///
/// Internal to the SDK.
void Function() onCancel(CancelToken token, void Function() callback) {
  if (token._cancelled) {
    callback();
    return _noop;
  }
  token._callbacks.add(callback);
  return () => token._callbacks.remove(callback);
}

void _noop() {}

/// Waits for a shared [future] while letting one caller stop waiting via its
/// own [token], without cancelling the shared operation for other waiters.
///
/// Internal to the SDK.
Future<T> waitFor<T>(
  Future<T> future,
  CancelToken? token,
  Object Function() onAbort,
) {
  if (token == null) return future;
  if (token.isCancelled) return Future<T>.error(onAbort());
  final completer = Completer<T>();
  final remove = onCancel(token, () {
    if (!completer.isCompleted) completer.completeError(onAbort());
  });
  future.then(
    (value) {
      remove();
      if (!completer.isCompleted) completer.complete(value);
    },
    onError: (Object error, StackTrace stack) {
      remove();
      if (!completer.isCompleted) completer.completeError(error, stack);
    },
  );
  return completer.future;
}
