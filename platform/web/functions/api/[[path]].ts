import worker, { type Env } from "../../worker";

export const onRequest: PagesFunction<Env> = async (context) => {
  return worker.fetch(context.request, context.env, {
    waitUntil: context.waitUntil.bind(context),
    passThroughOnException: () => undefined
  } as ExecutionContext);
};
