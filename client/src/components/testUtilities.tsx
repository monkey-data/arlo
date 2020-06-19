import React from 'react'
import { RenderResult, act, render } from '@testing-library/react'
import { createLocation, createMemoryHistory, MemoryHistory } from 'history'
import { match as routerMatch, Router } from 'react-router-dom'
import equal from 'fast-deep-equal'
import * as utilities from './utilities'

type MatchParameter<Params> = { [K in keyof Params]?: string }

const generateUrl = <Params extends MatchParameter<Params>>(
  path: string,
  params: Params
): string => {
  let tempPath = path

  for (const param in params) {
    /* istanbul ignore else */
    if (Object.prototype.hasOwnProperty.call(params, param)) {
      const value = params[param]
      tempPath = tempPath.replace(`:${param}`, value as NonNullable<
        typeof value
      >)
    }
  }

  return tempPath
}

export const routerTestProps = <Params extends MatchParameter<Params> = {}>(
  path: string,
  params: Params
) => {
  const match: routerMatch<Params> = {
    isExact: false,
    path,
    url: generateUrl(path, params),
    params,
  }
  const history = createMemoryHistory()
  const location = createLocation(match.url)

  return { history, location, match }
}

// Copied from https://testing-library.com/docs/example-react-router
export const renderWithRouter = (
  ui: React.ReactElement,
  {
    route = '/',
    history = createMemoryHistory({ initialEntries: [route] }),
  }: { route?: string; history?: MemoryHistory } = {}
) => {
  const Wrapper: React.FC = ({ children }: { children?: React.ReactNode }) => (
    <Router history={history}>{children}</Router>
  )

  return {
    ...render(ui, { wrapper: Wrapper }),
    // Adding `history` to the returned utilities to allow us
    // to reference it in our tests (just try to avoid using
    // this to test implementation details).
    history,
  }
}

interface ApiCall {
  endpoint: string
  options?: RequestInit
  response: object
}

export const mockApi = (apiCalls: ApiCall[]) => {
  const mock = jest
    .spyOn(utilities, 'api')
    .mockImplementation(async (endpoint: string, options?: RequestInit) => {
      const matchingCall = apiCalls.find(
        call => call.endpoint === endpoint && equal(call.options, options)
      )
      return matchingCall && matchingCall.response
    })

  return function checkMockApi() {
    const actualCalls = mock.mock.calls.map(([endpoint, options]) => ({
      endpoint,
      options,
    }))
    const expectedCalls = apiCalls.map(({ endpoint, options }) => ({
      endpoint,
      options,
    }))
    expect(actualCalls).toEqual(expectedCalls)
    mock.mockReset()
  }
}

/** Credit to https://stackoverflow.com/a/56452779 for solution to mocking React Router props */

export const regexpEscape = (s: string) => {
  /* eslint-disable no-useless-escape */
  return s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')
}

export const asyncActRender = async (
  component: React.ReactElement
): Promise<RenderResult> => {
  let result: RenderResult
  await act(() => {
    result = render(component)
  })
  return result!
}

export default {
  routerTestProps,
}
