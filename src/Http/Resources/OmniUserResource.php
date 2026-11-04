<?php

namespace KaziOmar\OmniAuth\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class OmniUserResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     * Automatically includes Spatie roles and permissions when available.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $data = parent::toArray($request);

        $includePermissions = config('omni-auth.permissions.include_in_response', true);

        if ($includePermissions) {
            // Auto-detect Spatie Permission or HasRoles trait methods
            if (method_exists($this->resource, 'getRoleNames')) {
                $roles = $this->resource->getRoleNames();
                $data['roles'] = is_iterable($roles) ? collect($roles)->values()->all() : (array) $roles;
            } elseif (isset($this->resource->role)) {
                $data['roles'] = [(string) $this->resource->role];
            }

            if (method_exists($this->resource, 'getAllPermissions')) {
                $permissions = $this->resource->getAllPermissions();
                if (is_iterable($permissions)) {
                    $data['permissions'] = collect($permissions)
                        ->map(fn($p) => is_object($p) && isset($p->name) ? $p->name : (string) $p)
                        ->values()
                        ->all();
                }
            } elseif (method_exists($this->resource, 'getPermissionNames')) {
                $permissions = $this->resource->getPermissionNames();
                $data['permissions'] = is_iterable($permissions) ? collect($permissions)->values()->all() : (array) $permissions;
            }
        }

        return $data;
    }
}
