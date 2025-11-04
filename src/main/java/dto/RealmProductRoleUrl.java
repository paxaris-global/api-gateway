package dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RealmProductRoleUrl {
    private Long id;

    private String url;

    private String uri;

    private RealmProductRole role;
}
