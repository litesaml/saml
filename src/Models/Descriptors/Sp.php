<?php

namespace Litesaml\Models\Descriptors;

class Sp extends Role
{
    public Endpoint $acs;

    public Endpoint $slo;
}
