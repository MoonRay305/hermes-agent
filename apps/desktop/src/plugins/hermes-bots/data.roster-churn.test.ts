/**
 * Bot roster polling must not turn the 5s React Query refetch into a source
 * lifecycle loop. The first fetch may warm the union inventory; immediate
 * refetches/rerenders must reuse that warm inventory and must not retain every
 * local/remote profile route as a live socket.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { ProfileRoute } from './types'

const { effectCleanups, hostMock, queryOptions } = vi.hoisted(() => ({
  effectCleanups: [] as Array<() => void>,
  hostMock: {
    agents: vi.fn(),
    profileRoutes: vi.fn(),
    request: vi.fn(),
    requestProfile: vi.fn(),
    retainProfileSocket: vi.fn(),
    state: {
      connectionId: { get: vi.fn(() => 'local') },
      profile: { get: vi.fn(() => 'default') }
    }
  },
  queryOptions: { current: null as null | { queryFn: () => Promise<unknown> } }
}))

vi.mock('react', () => ({
  useEffect: (effect: () => void | (() => void)) => {
    const cleanup = effect()

    if (typeof cleanup === 'function') {
      effectCleanups.push(cleanup)
    }
  }
}))

vi.mock('@hermes/plugin-sdk', async () => {
  const { atom } = await import('nanostores')

  return {
    atom,
    host: hostMock,
    queryClient: { getQueriesData: vi.fn(() => []), getQueryData: vi.fn(), invalidateQueries: vi.fn() },
    useQuery: vi.fn(options => {
      queryOptions.current = options

      return { data: null }
    }),
    useValue: vi.fn((store: { get?: () => unknown }) => store?.get?.())
  }
})

vi.mock('./shared', () => ({ getPluginCtx: () => null, ID: 'hermes-bots' }))
vi.mock('./labels', () => ({ displayName: vi.fn(() => 'Hermes') }))
vi.mock('./routing', async () => {
  const actual = await vi.importActual<typeof import('./routing')>('./routing')

  return {
    ...actual,
    requestForBot: vi.fn(async () => ({ profiles: [{ name: 'default' }] }))
  }
})

const route = (connectionId: string, profile: string, mode: ProfileRoute['mode'] = 'remote'): ProfileRoute => ({
  connectionId,
  mode,
  profile,
  targetProfile: profile
})

beforeEach(() => {
  vi.clearAllMocks()
  effectCleanups.splice(0).forEach(cleanup => cleanup())
  queryOptions.current = null
  hostMock.state.connectionId.get.mockReturnValue('local')
  hostMock.state.profile.get.mockReturnValue('default')
  hostMock.retainProfileSocket.mockReturnValue(vi.fn())
  hostMock.profileRoutes.mockResolvedValue([
    route('local', 'default', 'local'),
    route('local', 'research', 'local'),
    route('fresh-squiddy', 'default'),
    route('homelab', 'default')
  ])
  hostMock.agents.mockResolvedValue({
    agents: [
      { connectionId: 'local', connectionKind: 'local', profile: 'default' },
      { connectionId: 'fresh-squiddy', connectionKind: 'ssh', profile: 'default' }
    ],
    primaryConnectionId: 'local',
    sources: [
      { connectionId: 'local', kind: 'local', label: 'This device' },
      { connectionId: 'fresh-squiddy', kind: 'ssh', label: 'Fresh Squiddy', reachable: true }
    ]
  })
})

describe('roster poll source lifecycle (#BUI-1194)', () => {
  it('warms source inventory once and never retains every profile route', async () => {
    const { useRoster } = await import('./data')

    useRoster()
    expect(queryOptions.current).toBeTruthy()

    await queryOptions.current?.queryFn()
    await queryOptions.current?.queryFn()

    // A local active route stays registry-local so the SDK exemption can return
    // a no-op. The broken v2 conversion passed bare profile strings for every
    // local row and pinned one pooled socket per profile.
    expect(hostMock.retainProfileSocket).toHaveBeenCalledTimes(1)
    expect(hostMock.retainProfileSocket).toHaveBeenCalledWith({
      connectionId: 'local',
      mode: 'local',
      profile: 'default',
      targetProfile: 'default'
    })
    expect(hostMock.retainProfileSocket).not.toHaveBeenCalledWith('default')
    expect(hostMock.retainProfileSocket).not.toHaveBeenCalledWith('research')
    expect(hostMock.retainProfileSocket).not.toHaveBeenCalledWith(route('fresh-squiddy', 'default'))

    // The 5s roster refetch may reuse the warmed source snapshot; it must not
    // ask Electron to re-enumerate local/SSH sources on every tick.
    expect(hostMock.agents).toHaveBeenCalledTimes(1)
  })
})