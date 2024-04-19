<?php

namespace Litesaml\Models\Descriptors;

class Idp extends Role
{
    public Endpoint $sso;

    public Endpoint $slo;
}
