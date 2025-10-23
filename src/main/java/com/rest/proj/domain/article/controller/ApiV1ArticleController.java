package com.rest.proj.domain.article.controller;

import com.rest.proj.domain.article.entity.Article;
import com.rest.proj.domain.article.service.ArticleService;
import com.rest.proj.global.rsData.RsData;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/articles")
public class ApiV1ArticleController {
    private final ArticleService articleService;

    @GetMapping("")
    public RsData<List<Article>> getArticles() {
        List<Article> articles = articleService.getList();

        return RsData.of("S-1", "성공", articles);
    }

    @GetMapping("/{id}")
    public Article getArticle(@PathVariable("id") Long id) {
//        Article article = new Article((id));
        Article article = articleService.getArticle(id);

        return article;
    }
}
